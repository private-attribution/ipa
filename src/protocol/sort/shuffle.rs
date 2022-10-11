use crate::helpers::prss::PrssSpace;
use permutation::Permutation;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use embed_doc_image::embed_doc_image;
use futures::future::try_join_all;

use crate::{
    error::BoxError,
    field::Field,
    helpers::{
        mesh::{Gateway, Mesh},
        prss::SpaceIndex,
        Direction, Identity,
    },
    protocol::{context::ProtocolContext, RecordId, Step},
    secret_sharing::Replicated,
};

use super::{
    apply::apply_inv,
    reshare::Reshare,
    ShuffleStep::{self, Step1, Step2, Step3},
};

pub struct Shuffle<'a, F, SF> {
    input: &'a mut Vec<Replicated<F>>,
    step_fn: SF,
}

/// This is SHUFFLE(Algorithm 1) described in <https://eprint.iacr.org/2019/695.pdf>.
/// This protocol shuffles the given inputs across 3 helpers making them indistinguishable to the helpers
impl<'a, F: Field, S: Step + SpaceIndex, SF: Fn(ShuffleStep) -> S> Shuffle<'a, F, SF> {
    pub fn new(input: &'a mut Vec<Replicated<F>>, step_fn: SF) -> Self {
        Self { input, step_fn }
    }

    /// This implements Fisher Yates shuffle described here <https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle>
    #[allow(clippy::cast_possible_truncation)]
    fn generate_random_permutation(
        batchsize: usize,
        direction: Direction,
        prss: &PrssSpace,
        which_step: ShuffleStep,
    ) -> Permutation {
        // Chacha8Rng expects a [u8;32] seed whereas prss returns a u128 number.
        // We are using two seeds from prss to generate a seed for shuffle and concatenating them
        // Since reshare uses indexes 0..batchsize to generate random numbers from prss, we are using
        // batchsize and batchsize+1 as index to get seeds for permutation
        let randoms = (
            // Currently, PRSS is generating same random numbers across steps.
            // For shuffle, each step expects a different random number to act as a seed.
            prss.generate_values((batchsize + 2 * which_step.as_usize()) as u128),
            prss.generate_values((batchsize + 2 * which_step.as_usize() + 1) as u128),
        );
        println!(
            "index:{:?} {:?}",
            batchsize + 2 * which_step.as_usize(),
            randoms
        );
        let mut seed = Vec::with_capacity(32);
        if direction == Direction::Left {
            seed.extend_from_slice(&randoms.0 .0.to_le_bytes());
            seed.extend_from_slice(&randoms.1 .0.to_le_bytes());
        } else {
            seed.extend_from_slice(&randoms.0 .1.to_le_bytes());
            seed.extend_from_slice(&randoms.1 .1.to_le_bytes());
        };

        let mut permutation: Vec<usize> = (0..batchsize).collect();

        permutation.shuffle(&mut ChaCha8Rng::from_seed(seed.try_into().unwrap()));
        Permutation::from_vec(permutation)
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
    async fn reshare_all_shares<M, G>(
        &self,
        ctx: &ProtocolContext<'_, G, S>,
        which_step: ShuffleStep,
    ) -> Result<Vec<Replicated<F>>, BoxError>
    where
        M: Mesh,
        G: Gateway<M, S>,
    {
        let step = (self.step_fn)(which_step);
        let to_helper = Self::shuffle_for_helper(which_step);
        let reshares = self
            .input
            .iter()
            .enumerate()
            .map(|(index, input)| async move {
                Reshare::new(*input)
                    .execute(ctx, RecordId::from(index as u32), step, to_helper)
                    .await
            });
        try_join_all(reshares).await
    }

    /// `single_shuffle` is called for the helpers
    /// i)   2 helpers generate random sequence using shared prss random number
    /// ii)  2 helpers apply the permutation to their shares
    /// iii) reshare to `to_helper`
    async fn single_shuffle<M: Mesh, G: Gateway<M, S>>(
        &mut self,
        ctx: &ProtocolContext<'_, G, S>,
        which_step: ShuffleStep,
    ) -> Result<Vec<Replicated<F>>, BoxError> {
        let to_helper = Self::shuffle_for_helper(which_step);
        let step = (self.step_fn)(which_step);
        let prss = &ctx.participant[step];
        let channel = ctx.gateway.get_channel(step);

        if to_helper != channel.identity() {
            let direction = if to_helper.peer(Direction::Left) == channel.identity() {
                Direction::Left
            } else {
                Direction::Right
            };
            println!(
                "{:?} {:?}",
                channel.identity(),
                step,
            );
            let mut permute =
                Self::generate_random_permutation(self.input.len(), direction, prss, which_step);
            apply_inv(&mut permute, &mut self.input);
        }
        self.reshare_all_shares(ctx, which_step).await
    }
    #[embed_doc_image("shuffle", "images/sort/shuffle.png")]
    /// Shuffle calls `single_shuffle` three times with 2 helpers shuffling the shares each time.
    /// Order of calling `single_shuffle` is shuffle with (H2, H3), (H3, H1) and (H1, H2).
    /// ![Shuffle steps][shuffle]
    /// Each single shuffle requires communication between helpers to perform reshare.
    /// Infrastructure has a pre-requisite to distinguish each communication step uniquely.
    /// For this, we have three shuffle steps one per `single_shuffle` i.e. Step1, Step2 and Step3.
    /// The Shuffle object receives a step function and appends a `ShuffleStep` to form a concrete step
    pub async fn execute<M: Mesh, G: Gateway<M, S>>(
        &mut self,
        ctx: &ProtocolContext<'_, G, S>,
    ) -> Result<(), BoxError>
    where
        F: Field,
    {
        *self.input = self.single_shuffle(ctx, Step1).await.unwrap();
        *self.input = self.single_shuffle(ctx, Step2).await.unwrap();
        *self.input = self.single_shuffle(ctx, Step3).await.unwrap();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::Shuffle;
    use crate::{
        field::Fp31,
        helpers::Direction,
        protocol::sort::ShuffleStep::{self, Step1},
        protocol::QueryId,
        test_fixture::{
            generate_shares, make_contexts, make_participants, make_world,
            validate_and_reconstruct, TestStep, TestWorld,
        },
    };
    use permutation::Permutation;
    use tokio::try_join;

    #[test]
    fn random_sequence_generated() {
        let batchsize = 10000;
        let (p1, p2, p3) = make_participants();
        let sequence1left =
            Shuffle::<Fp31, fn(ShuffleStep) -> TestStep>::generate_random_permutation(
                batchsize,
                Direction::Left,
                &p1[TestStep::Shuffle(Step1)],
                Step1,
            );
        let sequence1right =
            Shuffle::<Fp31, fn(ShuffleStep) -> TestStep>::generate_random_permutation(
                batchsize,
                Direction::Right,
                &p1[TestStep::Shuffle(Step1)],
                Step1,
            );

        let sequence2left =
            Shuffle::<Fp31, fn(ShuffleStep) -> TestStep>::generate_random_permutation(
                batchsize,
                Direction::Left,
                &p2[TestStep::Shuffle(Step1)],
                Step1,
            );

        let sequence2right =
            Shuffle::<Fp31, fn(ShuffleStep) -> TestStep>::generate_random_permutation(
                batchsize,
                Direction::Right,
                &p2[TestStep::Shuffle(Step1)],
                Step1,
            );

        let sequence3left =
            Shuffle::<Fp31, fn(ShuffleStep) -> TestStep>::generate_random_permutation(
                batchsize,
                Direction::Left,
                &p3[TestStep::Shuffle(Step1)],
                Step1,
            );
        let sequence3right =
            Shuffle::<Fp31, fn(ShuffleStep) -> TestStep>::generate_random_permutation(
                batchsize,
                Direction::Right,
                &p3[TestStep::Shuffle(Step1)],
                Step1,
            );

        assert_eq!(sequence1right, sequence2left);
        assert_eq!(sequence2right, sequence3left);
        assert_eq!(sequence3right, sequence1left);

        // Due to less randomness, the below three asserts can fail. However, the chance of failure is
        // 1/18Quintillian (a billion billion since u64 is used to generate randomness)! Hopefully we should not hit that
        assert_ne!(sequence1left, sequence1right);
        assert_ne!(sequence2left, sequence2right);
        assert_ne!(sequence3left, sequence3right);

        assert!(Permutation::valid(&sequence1right));
        assert!(Permutation::valid(&sequence2right));
        assert!(Permutation::valid(&sequence3right));
    }

    #[tokio::test]
    async fn shuffle() {
        let world: TestWorld<TestStep> = make_world(QueryId);
        let context = make_contexts(&world);

        let batchsize = 25;
        let input: Vec<u8> = (0..batchsize).collect();
        let hashed_input: HashSet<u8> = input.clone().into_iter().collect();
        let input_len = input.len();

        let input_u128: Vec<u128> = input.iter().map(|x| u128::from(*x)).collect();
        let mut shares = generate_shares(input_u128);

        let input0 = shares.0.clone();
        let input1 = shares.1.clone();
        let input2 = shares.2.clone();

        let mut shuffle0 = Shuffle::new(&mut shares.0, TestStep::Shuffle);
        let mut shuffle1 = Shuffle::new(&mut shares.1, TestStep::Shuffle);
        let mut shuffle2 = Shuffle::new(&mut shares.2, TestStep::Shuffle);

        let h0_future = shuffle0.execute(&context[0]);
        let h1_future = shuffle1.execute(&context[1]);
        let h2_future = shuffle2.execute(&context[2]);

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
        (0..input_len).for_each(|i| {
            let val = validate_and_reconstruct((shares.0[i], shares.1[i], shares.2[i]));
            output_secret.push(u8::from(val));
            hashed_output_secret.insert(u8::from(val));

            result0.push(shares.0[i]);
            result1.push(shares.1[i]);
            result2.push(shares.2[i]);
        });

        // Order of shares should be different from input
        assert!(result0 != input0 || result1 != input1 || result2 != input2);

        // Secrets should be shuffled also
        assert_ne!(output_secret, input);

        // Shuffled output should have same inputs
        assert_eq!(hashed_output_secret, hashed_input);
    }
}
