use embed_doc_image::embed_doc_image;
use rand::{seq::SliceRandom, Rng};

use super::ShuffleStep::{self, Shuffle1, Shuffle2, Shuffle3};
use crate::{
    error::Error,
    ff::Field,
    helpers::{Direction, Role},
    protocol::{
        basics::{
            apply_permutation::{apply, apply_inv},
            Reshare,
        },
        context::Context,
        step::Step,
        NoRecord, RecordId,
    },
    secret_sharing::SecretSharing,
};

#[derive(Debug)]
/// This is SHUFFLE(Algorithm 1) described in <https://eprint.iacr.org/2019/695.pdf>.
/// This protocol shuffles the given inputs across 3 helpers making them indistinguishable to the helpers
/// We call shuffle with helpers involved as (H2, H3), (H3, H1) and (H1, H2). In other words, the shuffle is being called for
/// H1, H2 and H3 respectively (since they do not participate in the step) and hence are the recipients of the shuffle.
pub enum ShuffleOrUnshuffle {
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
pub fn get_two_of_three_random_permutations<R: Rng>(
    batch_size: u32,
    mut rng: (R, R),
) -> (Vec<u32>, Vec<u32>) {
    let mut left_permutation = (0..batch_size).collect::<Vec<_>>();
    let mut right_permutation = left_permutation.clone();

    left_permutation.shuffle(&mut rng.0);
    right_permutation.shuffle(&mut rng.1);

    (left_permutation, right_permutation)
}

pub(super) fn shuffle_for_helper(which_step: ShuffleStep) -> Role {
    match which_step {
        Shuffle1 => Role::H1,
        Shuffle2 => Role::H2,
        Shuffle3 => Role::H3,
    }
}

/// `shuffle_or_unshuffle_once` is called for the helpers
/// i)   2 helpers receive permutation pair and choose the permutation to be applied
/// ii)  2 helpers apply the permutation to their shares
/// iii) reshare to `to_helper`
#[tracing::instrument(name = "shuffle_once", skip_all, fields(to = ?shuffle_for_helper(which_step)))]
pub(crate) async fn shuffle_or_unshuffle_once<S, C>(
    mut input: Vec<S>,
    random_permutations: (&[u32], &[u32]),
    shuffle_or_unshuffle: ShuffleOrUnshuffle,
    ctx: &C,
    which_step: ShuffleStep,
) -> Result<Vec<S>, Error>
where
    C: Context,
    S: Reshare<C, RecordId> + Send + Sync,
{
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
    input.reshare(ctx, NoRecord, to_helper).await
}

#[embed_doc_image("shuffle", "images/sort/shuffle.png")]
/// Shuffle calls `shuffle_or_unshuffle_once` three times with 2 helpers shuffling the shares each time.
/// Order of calling `shuffle_or_unshuffle_once` is shuffle with (H2, H3), (H3, H1) and (H1, H2).
/// Each shuffle requires communication between helpers to perform reshare.
/// Infrastructure has a pre-requisite to distinguish each communication step uniquely.
/// For this, we have three shuffle steps one per `shuffle_or_unshuffle_once` i.e. Step1, Step2 and Step3.
/// The Shuffle object receives a step function and appends a `ShuffleStep` to form a concrete step
/// ![Shuffle steps][shuffle]
pub async fn shuffle_shares<F: Field, S: SecretSharing<F> + Reshare<C, RecordId>, C: Context>(
    input: Vec<S>,
    random_permutations: (&[u32], &[u32]),
    ctx: C,
) -> Result<Vec<S>, Error> {
    let input = shuffle_or_unshuffle_once(
        input,
        random_permutations,
        ShuffleOrUnshuffle::Shuffle,
        &ctx,
        Shuffle1,
    )
    .await?;
    let input = shuffle_or_unshuffle_once(
        input,
        random_permutations,
        ShuffleOrUnshuffle::Shuffle,
        &ctx,
        Shuffle2,
    )
    .await?;
    shuffle_or_unshuffle_once(
        input,
        random_permutations,
        ShuffleOrUnshuffle::Shuffle,
        &ctx,
        Shuffle3,
    )
    .await
}

#[embed_doc_image("unshuffle", "images/sort/unshuffle.png")]
/// Unshuffle calls `shuffle_or_unshuffle_once` three times with 2 helpers shuffling the shares each time in the opposite order to shuffle.
/// Order of calling `shuffle_or_unshuffle_once` is shuffle with (H1, H2), (H3, H1) and (H2, H3)
/// ![Unshuffle steps][unshuffle]
pub async fn unshuffle_shares<F: Field, S: SecretSharing<F> + Reshare<C, RecordId>, C: Context>(
    input: Vec<S>,
    random_permutations: (&[u32], &[u32]),
    ctx: C,
) -> Result<Vec<S>, Error> {
    let input = shuffle_or_unshuffle_once(
        input,
        random_permutations,
        ShuffleOrUnshuffle::Unshuffle,
        &ctx,
        Shuffle3,
    )
    .await?;
    let input = shuffle_or_unshuffle_once(
        input,
        random_permutations,
        ShuffleOrUnshuffle::Unshuffle,
        &ctx,
        Shuffle2,
    )
    .await?;
    shuffle_or_unshuffle_once(
        input,
        random_permutations,
        ShuffleOrUnshuffle::Unshuffle,
        &ctx,
        Shuffle1,
    )
    .await
}

#[cfg(all(test, unit_test))]
mod tests {
    use crate::{
        protocol::{sort::shuffle::get_two_of_three_random_permutations, step::Gate},
        rand::thread_rng,
        test_fixture::{make_participants, permutation_valid},
    };

    #[test]
    fn random_sequence_generated() {
        const BATCH_SIZE: u32 = 10000;

        let [p1, p2, p3] = make_participants(&mut thread_rng());
        let step = Gate::default();
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
        use std::collections::HashSet;

        use crate::{
            ff::{Field, Fp31},
            protocol::{
                context::Context,
                sort::shuffle::{
                    get_two_of_three_random_permutations, shuffle_shares, unshuffle_shares,
                },
            },
            test_fixture::{Reconstruct, Runner, TestWorld},
        };

        #[tokio::test]
        async fn semi_honest() {
            const BATCHSIZE: u8 = 25;
            let world = TestWorld::default();

            let input: Vec<u8> = (0..BATCHSIZE).collect();
            let hashed_input: HashSet<u8> = input.clone().into_iter().collect();

            let result = world
                .semi_honest(
                    input
                        .clone()
                        .into_iter()
                        .map(u128::from)
                        .map(Fp31::truncate_from),
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

            let world = TestWorld::default();
            let input: Vec<u128> = (0..u128::try_from(BATCHSIZE).unwrap()).collect();

            let result = world
                .semi_honest(
                    input.clone().into_iter().map(Fp31::truncate_from),
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
        use std::collections::HashSet;

        use crate::{
            ff::{Field, Fp31},
            protocol::{
                context::Context,
                sort::shuffle::{
                    get_two_of_three_random_permutations, shuffle_shares, unshuffle_shares,
                },
            },
            test_fixture::{Reconstruct, Runner, TestWorld},
        };

        #[tokio::test]
        async fn malicious() {
            const BATCHSIZE: u8 = 25;
            let world = TestWorld::default();

            let input: Vec<u8> = (0..BATCHSIZE).collect();
            let hashed_input: HashSet<u8> = input.clone().into_iter().collect();

            let input_u128: Vec<u128> = input.iter().map(|x| u128::from(*x)).collect();

            let result = world
                .upgraded_malicious(
                    input_u128.clone().into_iter().map(Fp31::truncate_from),
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
                output_secret.push(u8::try_from(val.as_u128()).unwrap());
                hashed_output_secret.insert(u8::try_from(val.as_u128()).unwrap());
            }

            // Secrets should be shuffled
            assert_ne!(output_secret, input);

            // Shuffled output should have same inputs
            assert_eq!(hashed_output_secret, hashed_input);
        }

        #[tokio::test]
        async fn shuffle_unshuffle() {
            const BATCHSIZE: usize = 5;

            let world = TestWorld::default();
            let input: Vec<u128> = (0..u128::try_from(BATCHSIZE).unwrap()).collect();

            let result = world
                .upgraded_malicious(
                    input.clone().into_iter().map(Fp31::truncate_from),
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
