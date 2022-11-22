use embed_doc_image::embed_doc_image;
use futures::future::try_join_all;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use crate::protocol::context::SemiHonestContext;
use crate::{
    error::BoxError,
    ff::Field,
    helpers::{Direction, Role},
    protocol::{context::Context, prss::IndexedSharedRandomness, RecordId, Substep},
    secret_sharing::Replicated,
};

use super::{
    apply::{apply, apply_inv},
    reshare::Reshare,
    ShuffleStep::{self, Step1, Step2, Step3},
};

#[derive(Debug)]
enum ShuffleOrUnshuffle {
    Shuffle,
    Unshuffle,
}

impl Substep for ShuffleOrUnshuffle {}
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
) -> (Vec<u32>, Vec<u32>) {
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

    let max_index: u32 = batchsize.try_into().unwrap();

    let mut permutations: (Vec<u32>, Vec<u32>) =
        ((0..max_index).collect(), (0..max_index).collect());
    // shuffle 0..N based on seed
    permutations
        .0
        .shuffle(&mut ChaCha8Rng::from_seed(seed_left.try_into().unwrap()));
    permutations
        .1
        .shuffle(&mut ChaCha8Rng::from_seed(seed_right.try_into().unwrap()));

    permutations
}

/// This is SHUFFLE(Algorithm 1) described in <https://eprint.iacr.org/2019/695.pdf>.
/// This protocol shuffles the given inputs across 3 helpers making them indistinguishable to the helpers

// We call shuffle with helpers involved as (H2, H3), (H3, H1) and (H1, H2). In other words, the shuffle is being called for
// H1, H2 and H3 respectively (since they do not participate in the step) and hence are the recipients of the shuffle.
fn shuffle_for_helper(which_step: ShuffleStep) -> Role {
    match which_step {
        Step1 => Role::H1,
        Step2 => Role::H2,
        Step3 => Role::H3,
    }
}

#[allow(clippy::cast_possible_truncation)]
async fn reshare_all_shares<F: Field>(
    input: Vec<Replicated<F>>,
    ctx: &SemiHonestContext<'_, F>,
    to_helper: Role,
) -> Result<Vec<Replicated<F>>, BoxError> {
    let reshares = input
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, input)| async move {
            Reshare::new(input)
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
async fn shuffle_or_unshuffle_once<F: Field>(
    mut input: Vec<Replicated<F>>,
    random_permutations: (&[u32], &[u32]),
    shuffle_or_unshuffle: ShuffleOrUnshuffle,
    ctx: &SemiHonestContext<'_, F>,
    which_step: ShuffleStep,
) -> Result<Vec<Replicated<F>>, BoxError> {
    let to_helper = shuffle_for_helper(which_step);
    let ctx = ctx.narrow(&which_step);

    if to_helper != ctx.role() {
        let permutation_to_apply = if to_helper.peer(Direction::Left) == ctx.role() {
            random_permutations.0
        } else {
            random_permutations.1
        };

        match shuffle_or_unshuffle {
            ShuffleOrUnshuffle::Shuffle => apply_inv(permutation_to_apply, &mut input),
            ShuffleOrUnshuffle::Unshuffle => apply(permutation_to_apply, &mut input),
        }
    }
    reshare_all_shares(input, &ctx, to_helper).await
}

#[embed_doc_image("shuffle", "images/sort/shuffle.png")]
/// Shuffle calls `shuffle_or_unshuffle_once` three times with 2 helpers shuffling the shares each time.
/// Order of calling `shuffle_or_unshuffle_once` is shuffle with (H2, H3), (H3, H1) and (H1, H2).
/// Each shuffle requires communication between helpers to perform reshare.
/// Infrastructure has a pre-requisite to distinguish each communication step uniquely.
/// For this, we have three shuffle steps one per `shuffle_or_unshuffle_once` i.e. Step1, Step2 and Step3.
/// The Shuffle object receives a step function and appends a `ShuffleStep` to form a concrete step
/// ![Shuffle steps][shuffle]
pub async fn shuffle_shares<F: Field>(
    input: Vec<Replicated<F>>,
    random_permutations: (&[u32], &[u32]),
    ctx: SemiHonestContext<'_, F>,
) -> Result<Vec<Replicated<F>>, BoxError> {
    let input = shuffle_or_unshuffle_once(
        input,
        random_permutations,
        ShuffleOrUnshuffle::Shuffle,
        &ctx,
        Step1,
    )
    .await?;
    let input = shuffle_or_unshuffle_once(
        input,
        random_permutations,
        ShuffleOrUnshuffle::Shuffle,
        &ctx,
        Step2,
    )
    .await?;
    shuffle_or_unshuffle_once(
        input,
        random_permutations,
        ShuffleOrUnshuffle::Shuffle,
        &ctx,
        Step3,
    )
    .await
}

#[embed_doc_image("unshuffle", "images/sort/unshuffle.png")]
/// Unshuffle calls `shuffle_or_unshuffle_once` three times with 2 helpers shuffling the shares each time in the opposite order to shuffle.
/// Order of calling `shuffle_or_unshuffle_once` is shuffle with (H1, H2), (H3, H1) and (H2, H3)
/// ![Unshuffle steps][unshuffle]
pub async fn unshuffle_shares<F: Field>(
    input: Vec<Replicated<F>>,
    random_permutations: (&[u32], &[u32]),
    ctx: SemiHonestContext<'_, F>,
) -> Result<Vec<Replicated<F>>, BoxError> {
    let input = shuffle_or_unshuffle_once(
        input,
        random_permutations,
        ShuffleOrUnshuffle::Unshuffle,
        &ctx,
        Step3,
    )
    .await?;
    let input = shuffle_or_unshuffle_once(
        input,
        random_permutations,
        ShuffleOrUnshuffle::Unshuffle,
        &ctx,
        Step2,
    )
    .await?;
    shuffle_or_unshuffle_once(
        input,
        random_permutations,
        ShuffleOrUnshuffle::Unshuffle,
        &ctx,
        Step1,
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::iter::zip;

    use crate::protocol::context::Context;
    use crate::test_fixture::{logging, validate_list_of_shares};
    use crate::{
        ff::Fp31,
        protocol::{
            sort::shuffle::{
                get_two_of_three_random_permutations, shuffle_shares, unshuffle_shares,
                ShuffleOrUnshuffle,
            },
            QueryId, Step,
        },
        test_fixture::{
            generate_shares, make_contexts, make_participants, make_world, narrow_contexts,
            permutation_valid, validate_and_reconstruct, TestWorld,
        },
    };
    use futures::future::try_join_all;

    #[test]
    fn random_sequence_generated() {
        const BATCH_SIZE: usize = 10000;

        logging::setup();

        let (p1, p2, p3) = make_participants();
        let step = Step::default();
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

        assert!(permutation_valid(&perm1.0));
        assert!(permutation_valid(&perm2.0));
        assert!(permutation_valid(&perm3.0));
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
        let shares = generate_shares(&input_u128);

        let original = shares.clone();

        let perm1 = get_two_of_three_random_permutations(input_len, context[0].prss().as_ref());
        let perm2 = get_two_of_three_random_permutations(input_len, context[1].prss().as_ref());
        let perm3 = get_two_of_three_random_permutations(input_len, context[2].prss().as_ref());

        let [c0, c1, c2] = context;

        let [shares0, shares1, shares2] = shares;
        let h0_future = shuffle_shares(shares0, (&perm1.0, &perm1.1), c0);
        let h1_future = shuffle_shares(shares1, (&perm2.0, &perm2.1), c1);
        let h2_future = shuffle_shares(shares2, (&perm3.0, &perm3.1), c2);

        let results: [_; 3] = try_join_all([h0_future, h1_future, h2_future])
            .await
            .unwrap()
            .try_into()
            .unwrap();

        let mut hashed_output_secret = HashSet::new();
        let mut output_secret = Vec::new();
        for (r0, (r1, r2)) in zip(results[0].iter(), zip(results[1].iter(), results[2].iter())) {
            let val = validate_and_reconstruct(r0, r1, r2);
            output_secret.push(u8::from(val));
            hashed_output_secret.insert(u8::from(val));
        }

        // Order of shares should now be different from original
        assert_ne!(results, original);
        // Secrets should be shuffled also
        assert_ne!(output_secret, input);

        // Shuffled output should have same inputs
        assert_eq!(hashed_output_secret, hashed_input);
    }

    #[tokio::test]
    async fn shuffle_unshuffle() {
        const BATCHSIZE: usize = 5;

        let world: TestWorld = make_world(QueryId);
        let context = make_contexts::<Fp31>(&world);

        let input: Vec<u128> = (0..u128::try_from(BATCHSIZE).unwrap()).collect();

        let shares = generate_shares(&input);

        let perm1 = get_two_of_three_random_permutations(BATCHSIZE, context[0].prss().as_ref());
        let perm2 = get_two_of_three_random_permutations(BATCHSIZE, context[1].prss().as_ref());
        let perm3 = get_two_of_three_random_permutations(BATCHSIZE, context[2].prss().as_ref());

        let shuffled: [_; 3] = {
            let [ctx0, ctx1, ctx2] = narrow_contexts(&context, &ShuffleOrUnshuffle::Shuffle);
            let [shares0, shares1, shares2] = shares;
            let h0_future = shuffle_shares(shares0, (&perm1.0, &perm1.1), ctx0);
            let h1_future = shuffle_shares(shares1, (&perm2.0, &perm2.1), ctx1);
            let h2_future = shuffle_shares(shares2, (&perm3.0, &perm3.1), ctx2);

            try_join_all([h0_future, h1_future, h2_future])
                .await
                .unwrap()
                .try_into()
                .unwrap()
        };
        let unshuffled: [_; 3] = {
            let [ctx0, ctx1, ctx2] = narrow_contexts(&context, &ShuffleOrUnshuffle::Unshuffle);
            let [shuffled0, shuffled1, shuffled2] = shuffled;
            let h0_future = unshuffle_shares(shuffled0, (&perm1.0, &perm1.1), ctx0);
            let h1_future = unshuffle_shares(shuffled1, (&perm2.0, &perm2.1), ctx1);
            let h2_future = unshuffle_shares(shuffled2, (&perm3.0, &perm3.1), ctx2);

            // When unshuffle and shuffle are called with same step, they undo each other's effect
            try_join_all([h0_future, h1_future, h2_future])
                .await
                .unwrap()
                .try_into()
                .unwrap()
        };

        validate_list_of_shares(&input[..], &unshuffled);
    }
}
