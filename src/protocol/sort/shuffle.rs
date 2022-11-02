use embed_doc_image::embed_doc_image;
use futures::future::try_join_all;
use permutation::Permutation;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use crate::{
    error::BoxError,
    ff::Field,
    helpers::{Direction, Identity},
    protocol::{context::ProtocolContext, prss::IndexedSharedRandomness, RecordId, Step},
    secret_sharing::Replicated,
};

use super::{
    apply::{apply, apply_inv},
    reshare::Reshare,
    ShuffleStep::{self, Step1, Step2, Step3},
};

pub struct Shuffle<'a, F> {
    input: &'a mut Vec<Replicated<F>>,
}

#[derive(Debug)]
enum ShuffleOrUnshuffle {
    Shuffle,
    Unshuffle,
}

impl Step for ShuffleOrUnshuffle {}
impl AsRef<str> for ShuffleOrUnshuffle {
    fn as_ref(&self) -> &str {
        match self {
            Self::Shuffle => "shuffle",
            Self::Unshuffle => "unshuffle",
        }
    }
}

/// This implements Fisher Yates shuffle described here <https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle>
#[allow(clippy::cast_possible_truncation)]
pub fn get_two_of_three_random_permutations(
    batchsize: usize,
    prss: &IndexedSharedRandomness,
) -> (Permutation, Permutation) {
    // Chacha8Rng expects a [u8;32] seed whereas prss returns a u128 number.
    // We are using two seeds from prss to generate a seed for shuffle and concatenating them
    // Since reshare uses indexes 0..batchsize to generate random numbers from prss, we are using
    // batchsize and batchsize+1 as index to get seeds for permutation
    let randoms = (
        prss.generate_values(batchsize as u128),
        prss.generate_values(batchsize as u128 + 1),
    );

    // generate seed for shuffle
    let (mut seed_left, mut seed_right) = (Vec::with_capacity(32), Vec::with_capacity(32));
    seed_left.extend_from_slice(&randoms.0 .0.to_le_bytes());
    seed_left.extend_from_slice(&randoms.1 .0.to_le_bytes());

    seed_right.extend_from_slice(&randoms.0 .1.to_le_bytes());
    seed_right.extend_from_slice(&randoms.1 .1.to_le_bytes());

    let mut permutations: (Vec<usize>, Vec<usize>) =
        ((0..batchsize).collect(), (0..batchsize).collect());
    // shuffle 0..N based on seed
    permutations
        .0
        .shuffle(&mut ChaCha8Rng::from_seed(seed_left.try_into().unwrap()));
    permutations
        .1
        .shuffle(&mut ChaCha8Rng::from_seed(seed_right.try_into().unwrap()));

    (
        Permutation::oneline(permutations.0),
        Permutation::oneline(permutations.1),
    )
}

/// This is SHUFFLE(Algorithm 1) described in <https://eprint.iacr.org/2019/695.pdf>.
/// This protocol shuffles the given inputs across 3 helpers making them indistinguishable to the helpers
impl<'a, F: Field> Shuffle<'a, F> {
    pub fn new(input: &'a mut Vec<Replicated<F>>) -> Self {
        Self { input }
    }

    // We call shuffle with helpers involved as (H2, H3), (H3, H1) and (H1, H2). In other words, the shuffle is being called for
    // H1, H2 and H3 respectively (since they do not participate in the step) and hence are the recipients of the shuffle.
    fn shuffle_for_helper(which_step: ShuffleStep) -> Identity {
        match which_step {
            Step1 => Identity::H1,
            Step2 => Identity::H2,
            Step3 => Identity::H3,
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    async fn reshare_all_shares(
        &self,
        ctx: &ProtocolContext<'_, F>,
        to_helper: Identity,
    ) -> Result<Vec<Replicated<F>>, BoxError> {
        let reshares = self
            .input
            .iter()
            .enumerate()
            .map(|(index, input)| async move {
                Reshare::new(*input)
                    .execute(ctx, RecordId::from(index), to_helper)
                    .await
            });
        try_join_all(reshares).await
    }

    /// `shuffle_or_unshuffle_once` is called for the helpers
    /// i)   2 helpers receive permutation pair and choose the permutation to be applied
    /// ii)  2 helpers apply the permutation to their shares
    /// iii) reshare to `to_helper`
    #[allow(clippy::cast_possible_truncation)]
    async fn shuffle_or_unshuffle_once(
        &mut self,
        shuffle_or_unshuffle: ShuffleOrUnshuffle,
        ctx: &ProtocolContext<'_, F>,
        which_step: ShuffleStep,
        permutations: &mut (Permutation, Permutation),
    ) -> Result<Vec<Replicated<F>>, BoxError> {
        let to_helper = Self::shuffle_for_helper(which_step);
        let ctx = ctx.narrow(&which_step);

        if to_helper != ctx.role() {
            let permute = if to_helper.peer(Direction::Left) == ctx.role() {
                &mut permutations.0
            } else {
                &mut permutations.1
            };

            match shuffle_or_unshuffle {
                ShuffleOrUnshuffle::Shuffle => apply_inv(permute, self.input),
                ShuffleOrUnshuffle::Unshuffle => apply(permute, self.input),
            }
        }
        self.reshare_all_shares(&ctx, to_helper).await
    }

    #[embed_doc_image("shuffle", "images/sort/shuffle.png")]
    /// Shuffle calls `shuffle_or_unshuffle_once` three times with 2 helpers shuffling the shares each time.
    /// Order of calling `shuffle_or_unshuffle_once` is shuffle with (H2, H3), (H3, H1) and (H1, H2).
    /// Each shuffle requires communication between helpers to perform reshare.
    /// Infrastructure has a pre-requisite to distinguish each communication step uniquely.
    /// For this, we have three shuffle steps one per `shuffle_or_unshuffle_once` i.e. Step1, Step2 and Step3.
    /// The Shuffle object receives a step function and appends a `ShuffleStep` to form a concrete step
    /// ![Shuffle steps][shuffle]
    #[allow(dead_code)]
    pub async fn execute(
        &mut self,
        ctx: ProtocolContext<'_, F>,
        permutations: &mut (Permutation, Permutation),
    ) -> Result<(), BoxError>
    where
        F: Field,
    {
        *self.input = self
            .shuffle_or_unshuffle_once(ShuffleOrUnshuffle::Shuffle, &ctx, Step1, permutations)
            .await
            .unwrap();
        *self.input = self
            .shuffle_or_unshuffle_once(ShuffleOrUnshuffle::Shuffle, &ctx, Step2, permutations)
            .await
            .unwrap();
        *self.input = self
            .shuffle_or_unshuffle_once(ShuffleOrUnshuffle::Shuffle, &ctx, Step3, permutations)
            .await
            .unwrap();

        Ok(())
    }

    #[embed_doc_image("unshuffle", "images/sort/unshuffle.png")]
    /// Unshuffle calls `shuffle_or_unshuffle_once` three times with 2 helpers shuffling the shares each time in the opposite order to shuffle.
    /// Order of calling `shuffle_or_unshuffle_once` is shuffle with (H1, H2), (H3, H1) and (H2, H3)
    /// ![Unshuffle steps][unshuffle]
    pub async fn execute_unshuffle(
        &mut self,
        ctx: ProtocolContext<'_, F>,
        permutations: &mut (Permutation, Permutation),
    ) -> Result<(), BoxError>
    where
        F: Field,
    {
        *self.input = self
            .shuffle_or_unshuffle_once(ShuffleOrUnshuffle::Unshuffle, &ctx, Step3, permutations)
            .await
            .unwrap();
        *self.input = self
            .shuffle_or_unshuffle_once(ShuffleOrUnshuffle::Unshuffle, &ctx, Step2, permutations)
            .await
            .unwrap();
        *self.input = self
            .shuffle_or_unshuffle_once(ShuffleOrUnshuffle::Unshuffle, &ctx, Step1, permutations)
            .await
            .unwrap();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::test_fixture::logging;
    use crate::{
        ff::Fp31,
        protocol::{
            sort::shuffle::{get_two_of_three_random_permutations, Shuffle, ShuffleOrUnshuffle},
            QueryId, UniqueStepId,
        },
        test_fixture::{
            generate_shares, make_contexts, make_participants, make_world, narrow_contexts,
            validate_and_reconstruct, TestWorld,
        },
    };
    use permutation::Permutation;
    use tokio::try_join;

    #[test]
    fn random_sequence_generated() {
        const BATCH_SIZE: usize = 10000;

        logging::setup();

        let (p1, p2, p3) = make_participants();
        let step = UniqueStepId::default();
        let perm1 = get_two_of_three_random_permutations(BATCH_SIZE, p1.indexed(&step).as_ref());
        let perm2 = get_two_of_three_random_permutations(BATCH_SIZE, p2.indexed(&step).as_ref());
        let perm3 = get_two_of_three_random_permutations(BATCH_SIZE, p3.indexed(&step).as_ref());

        assert_eq!(perm1.1, perm2.0);
        assert_eq!(perm2.1, perm3.0);
        assert_eq!(perm3.1, perm1.0);

        // Due to less randomness, the below three asserts can fail. However, the chance of failure is
        // 1/18Quintillian (a billion billion since u64 is used to generate randomness)! Hopefully we should not hit that
        assert_ne!(perm1.0, perm1.1);
        assert_ne!(perm2.0, perm2.1);
        assert_ne!(perm3.0, perm3.1);

        assert!(Permutation::valid(&perm1.0));
        assert!(Permutation::valid(&perm2.0));
        assert!(Permutation::valid(&perm3.0));
    }

    #[tokio::test]
    async fn shuffle() {
        let world: TestWorld = make_world(QueryId);
        let context = make_contexts::<Fp31>(&world);

        let batchsize = 25;
        let input: Vec<u8> = (0..batchsize).collect();
        let hashed_input: HashSet<u8> = input.clone().into_iter().collect();
        let input_len = input.len();

        let input_u128: Vec<u128> = input.iter().map(|x| u128::from(*x)).collect();
        let mut shares = generate_shares(input_u128);

        let input0 = shares.0.clone();
        let input1 = shares.1.clone();
        let input2 = shares.2.clone();

        let mut perm1 = get_two_of_three_random_permutations(input_len, context[0].prss().as_ref());
        let mut perm2 = get_two_of_three_random_permutations(input_len, context[1].prss().as_ref());
        let mut perm3 = get_two_of_three_random_permutations(input_len, context[2].prss().as_ref());

        let [c0, c1, c2] = context;
        let mut shuffle0 = Shuffle::new(&mut shares.0);
        let mut shuffle1 = Shuffle::new(&mut shares.1);
        let mut shuffle2 = Shuffle::new(&mut shares.2);

        let h0_future = shuffle0.execute(c0, &mut perm1);
        let h1_future = shuffle1.execute(c1, &mut perm2);
        let h2_future = shuffle2.execute(c2, &mut perm3);

        try_join!(h0_future, h1_future, h2_future).unwrap();

        // Shuffled output should be same length as input
        assert_eq!(shares.0.len(), input_len);
        assert_eq!(shares.1.len(), input_len);
        assert_eq!(shares.2.len(), input_len);

        let mut result0 = Vec::with_capacity(input_len);
        let mut result1 = Vec::with_capacity(input_len);
        let mut result2 = Vec::with_capacity(input_len);

        let mut hashed_output_secret = HashSet::new();
        let mut output_secret = Vec::new();
        (0..shares.0.len()).for_each(|i| {
            let val = validate_and_reconstruct((shares.0[i], shares.1[i], shares.2[i]));
            output_secret.push(u8::from(val));
            hashed_output_secret.insert(u8::from(val));

            result0.push(shares.0[i]);
            result1.push(shares.1[i]);
            result2.push(shares.2[i]);
        });

        // Order of shares should now be different from original
        assert!(result0 != input0 || result1 != input1 || result2 != input2);
        // Secrets should be shuffled also
        assert_ne!(output_secret, input);

        // Shuffled output should have same inputs
        assert_eq!(hashed_output_secret, hashed_input);
    }

    #[tokio::test]
    async fn shuffle_unshuffle() {
        let world: TestWorld = make_world(QueryId);
        let context = make_contexts::<Fp31>(&world);

        let batchsize = 5;
        let input: Vec<u128> = (0..batchsize).collect();

        let input_fielded: Vec<Fp31> = input.iter().map(|x| Fp31::from(*x)).collect();
        let input_len = input.len();

        let mut shares = generate_shares(input);

        let mut perm1 = get_two_of_three_random_permutations(input_len, context[0].prss().as_ref());
        let mut perm2 = get_two_of_three_random_permutations(input_len, context[1].prss().as_ref());
        let mut perm3 = get_two_of_three_random_permutations(input_len, context[2].prss().as_ref());

        {
            let [ctx0, ctx1, ctx2] = narrow_contexts(&context, &ShuffleOrUnshuffle::Shuffle);
            let mut shuffle0 = Shuffle::new(&mut shares.0);
            let mut shuffle1 = Shuffle::new(&mut shares.1);
            let mut shuffle2 = Shuffle::new(&mut shares.2);

            let h0_future = shuffle0.execute(ctx0, &mut perm1);
            let h1_future = shuffle1.execute(ctx1, &mut perm2);
            let h2_future = shuffle2.execute(ctx2, &mut perm3);

            try_join!(h0_future, h1_future, h2_future).unwrap();
        }
        {
            let [ctx0, ctx1, ctx2] = narrow_contexts(&context, &ShuffleOrUnshuffle::Unshuffle);
            let mut unshuffle0 = Shuffle::new(&mut shares.0);
            let mut unshuffle1 = Shuffle::new(&mut shares.1);
            let mut unshuffle2 = Shuffle::new(&mut shares.2);

            // When unshuffle and shuffle are called with same step, they undo each other's effect
            let h0_future = unshuffle0.execute_unshuffle(ctx0, &mut perm1);
            let h1_future = unshuffle1.execute_unshuffle(ctx1, &mut perm2);
            let h2_future = unshuffle2.execute_unshuffle(ctx2, &mut perm3);

            try_join!(h0_future, h1_future, h2_future).unwrap();
        }

        let mut result = Vec::with_capacity(input_len);

        (0..shares.0.len()).for_each(|i| {
            result.push(validate_and_reconstruct((
                shares.0[i],
                shares.1[i],
                shares.2[i],
            )));
        });

        assert_eq!(result, input_fielded);
    }
}
