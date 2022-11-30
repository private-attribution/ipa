use std::iter::{repeat, zip};

use embed_doc_image::embed_doc_image;
use futures::future::try_join_all;
use rand::seq::SliceRandom;

use crate::protocol::prss::SequentialSharedRandomness;
use crate::secret_sharing::SecretSharing;
use crate::{
    error::Error,
    ff::Field,
    helpers::{Direction, Role},
    protocol::{context::Context, RecordId, Substep},
};

use super::{
    apply::{apply, apply_inv},
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
pub fn get_two_of_three_random_permutations(
    batch_size: u32,
    mut rng: (SequentialSharedRandomness, SequentialSharedRandomness),
) -> (Vec<u32>, Vec<u32>) {
    let mut left_permutation = (0..batch_size).collect::<Vec<_>>();
    let mut right_permutation = left_permutation.clone();

    left_permutation.shuffle(&mut rng.0);
    right_permutation.shuffle(&mut rng.1);

    (left_permutation, right_permutation)
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

async fn reshare_all_shares<F: Field, S: SecretSharing<F>, C: Context<F, Share = S>>(
    input: &[S],
    ctx: C,
    to_helper: Role,
) -> Result<Vec<S>, Error> {
    let reshares = zip(repeat(ctx), input)
        .enumerate()
        .map(|(index, (ctx, input))| async move {
            ctx.reshare(input, RecordId::from(index), to_helper).await
        });
    try_join_all(reshares).await
}

/// `shuffle_or_unshuffle_once` is called for the helpers
/// i)   2 helpers receive permutation pair and choose the permutation to be applied
/// ii)  2 helpers apply the permutation to their shares
/// iii) reshare to `to_helper`
async fn shuffle_or_unshuffle_once<F: Field, S: SecretSharing<F>, C: Context<F, Share = S>>(
    mut input: Vec<S>,
    random_permutations: (&[u32], &[u32]),
    shuffle_or_unshuffle: ShuffleOrUnshuffle,
    ctx: &C,
    which_step: ShuffleStep,
) -> Result<Vec<S>, Error> {
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
    reshare_all_shares(&input, ctx, to_helper).await
}

#[embed_doc_image("shuffle", "images/sort/shuffle.png")]
/// Shuffle calls `shuffle_or_unshuffle_once` three times with 2 helpers shuffling the shares each time.
/// Order of calling `shuffle_or_unshuffle_once` is shuffle with (H2, H3), (H3, H1) and (H1, H2).
/// Each shuffle requires communication between helpers to perform reshare.
/// Infrastructure has a pre-requisite to distinguish each communication step uniquely.
/// For this, we have three shuffle steps one per `shuffle_or_unshuffle_once` i.e. Step1, Step2 and Step3.
/// The Shuffle object receives a step function and appends a `ShuffleStep` to form a concrete step
/// ![Shuffle steps][shuffle]
pub async fn shuffle_shares<F: Field, S: SecretSharing<F>, C: Context<F, Share = S>>(
    input: Vec<S>,
    random_permutations: (&[u32], &[u32]),
    ctx: C,
) -> Result<Vec<S>, Error> {
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
pub async fn unshuffle_shares<F: Field, S: SecretSharing<F>, C: Context<F, Share = S>>(
    input: Vec<S>,
    random_permutations: (&[u32], &[u32]),
    ctx: C,
) -> Result<Vec<S>, Error> {
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

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {

    use crate::{
        protocol::{sort::shuffle::get_two_of_three_random_permutations, Step},
        test_fixture::{permutation_valid, ParticipantSetup},
    };

    #[test]
    fn random_sequence_generated() {
        const BATCH_SIZE: u32 = 10000;

        let [p1, p2, p3] = ParticipantSetup::default().into_participants();
        let step = Step::default();
        let perm1 = get_two_of_three_random_permutations(BATCH_SIZE, p1.sequential(&step));
        let perm2 = get_two_of_three_random_permutations(BATCH_SIZE, p2.sequential(&step));
        let perm3 = get_two_of_three_random_permutations(BATCH_SIZE, p3.sequential(&step));

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

    mod semi_honest {
        use crate::ff::Fp31;
        use crate::protocol::context::Context;
        use crate::protocol::sort::shuffle::{
            get_two_of_three_random_permutations, shuffle_shares, unshuffle_shares,
        };
        use crate::protocol::QueryId;
        use crate::test_fixture::{Reconstruct, Runner, TestWorld};
        use std::collections::HashSet;

        #[tokio::test]
        async fn semi_honest() {
            const BATCHSIZE: u8 = 25;
            let world = TestWorld::new(QueryId);

            let input: Vec<u8> = (0..BATCHSIZE).collect();
            let hashed_input: HashSet<u8> = input.clone().into_iter().collect();

            let result = world
                .semi_honest(
                    input.clone().into_iter().map(u128::from).map(Fp31::from),
                    |ctx, m_shares| async move {
                        let perms =
                            get_two_of_three_random_permutations(BATCHSIZE.into(), ctx.prss_rng());
                        shuffle_shares(
                            m_shares,
                            (perms.0.as_slice(), perms.1.as_slice()),
                            ctx.clone(),
                        )
                        .await
                        .unwrap()
                    },
                )
                .await;

            let mut hashed_output_secret = HashSet::new();
            let mut output_secret = Vec::new();
            for val in result.reconstruct() {
                output_secret.push(u8::from(val));
                hashed_output_secret.insert(u8::from(val));
            }

            // Secrets should be shuffled
            assert_ne!(output_secret, input);

            // Shuffled output should have same inputs
            assert_eq!(hashed_output_secret, hashed_input);
        }

        #[tokio::test]
        async fn shuffle_unshuffle() {
            const BATCHSIZE: usize = 5;

            let world = TestWorld::new(QueryId);
            let input: Vec<u128> = (0..u128::try_from(BATCHSIZE).unwrap()).collect();

            let result = world
                .semi_honest(
                    input.clone().into_iter().map(Fp31::from),
                    |ctx, m_shares| async move {
                        let perms = get_two_of_three_random_permutations(
                            BATCHSIZE.try_into().unwrap(),
                            ctx.prss_rng(),
                        );
                        let shuffled = shuffle_shares(
                            m_shares,
                            (perms.0.as_slice(), perms.1.as_slice()),
                            ctx.clone(),
                        )
                        .await
                        .unwrap();

                        unshuffle_shares(
                            shuffled,
                            (perms.0.as_slice(), perms.1.as_slice()),
                            ctx.narrow("unshuffle"),
                        )
                        .await
                        .unwrap()
                    },
                )
                .await;

            assert_eq!(&input[..], &result.reconstruct());
        }
    }

    mod malicious {
        use crate::ff::Fp31;
        use crate::protocol::context::Context;
        use crate::protocol::sort::shuffle::{
            get_two_of_three_random_permutations, shuffle_shares, unshuffle_shares,
        };
        use crate::protocol::QueryId;
        use crate::test_fixture::{Reconstruct, Runner, TestWorld};
        use std::collections::HashSet;

        #[tokio::test]
        async fn malicious() {
            const BATCHSIZE: u8 = 25;
            let world = TestWorld::new(QueryId);

            let input: Vec<u8> = (0..BATCHSIZE).collect();
            let hashed_input: HashSet<u8> = input.clone().into_iter().collect();

            let input_u128: Vec<u128> = input.iter().map(|x| u128::from(*x)).collect();

            let result = world
                .malicious(
                    input_u128.clone().into_iter().map(Fp31::from),
                    |ctx, m_shares| async move {
                        let perms =
                            get_two_of_three_random_permutations(BATCHSIZE.into(), ctx.prss_rng());
                        shuffle_shares(
                            m_shares,
                            (perms.0.as_slice(), perms.1.as_slice()),
                            ctx.clone(),
                        )
                        .await
                        .unwrap()
                    },
                )
                .await;

            let mut hashed_output_secret = HashSet::new();
            let mut output_secret = Vec::new();
            for val in result.reconstruct() {
                output_secret.push(u8::from(val));
                hashed_output_secret.insert(u8::from(val));
            }

            // Secrets should be shuffled
            assert_ne!(output_secret, input);

            // Shuffled output should have same inputs
            assert_eq!(hashed_output_secret, hashed_input);
        }

        #[tokio::test]
        async fn shuffle_unshuffle() {
            const BATCHSIZE: usize = 5;

            let world = TestWorld::new(QueryId);
            let input: Vec<u128> = (0..u128::try_from(BATCHSIZE).unwrap()).collect();

            let result = world
                .malicious(
                    input.clone().into_iter().map(Fp31::from),
                    |ctx, m_shares| async move {
                        let perms = get_two_of_three_random_permutations(
                            BATCHSIZE.try_into().unwrap(),
                            ctx.prss_rng(),
                        );
                        let shuffled = shuffle_shares(
                            m_shares,
                            (perms.0.as_slice(), perms.1.as_slice()),
                            ctx.clone(),
                        )
                        .await
                        .unwrap();

                        unshuffle_shares(
                            shuffled,
                            (perms.0.as_slice(), perms.1.as_slice()),
                            ctx.narrow("unshuffle"),
                        )
                        .await
                        .unwrap()
                    },
                )
                .await;

            assert_eq!(&input[..], &result.reconstruct());
        }
    }
}
