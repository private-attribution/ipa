use embed_doc_image::embed_doc_image;
use ipa_macros::Step;

use crate::{
    error::Error,
    helpers::Direction,
    protocol::{
        basics::Reshare,
        context::Context,
        sort::{
            apply::{apply, apply_inv},
            shuffle::{shuffle_for_helper, ShuffleOrUnshuffle},
            ShuffleStep::{self, Shuffle1, Shuffle2, Shuffle3},
        },
        NoRecord, RecordId,
    },
};

#[derive(Step)]
pub(crate) enum InnerVectorElementStep {
    #[dynamic(64)]
    Elem(usize),
}

impl From<usize> for InnerVectorElementStep {
    fn from(v: usize) -> Self {
        Self::Elem(v)
    }
}

/// `shuffle_once` is called for the helpers
/// i)   2 helpers receive permutation pair and choose the permutation to be applied
/// ii)  2 helpers apply the permutation to their shares
/// iii) reshare to `to_helper`
#[tracing::instrument(name = "shuffle_once", skip_all, fields(to = ?shuffle_for_helper(which_step)))]
async fn shuffle_once<C, I>(
    mut input: Vec<I>,
    random_permutations: (&[u32], &[u32]),
    shuffle_or_unshuffle: ShuffleOrUnshuffle,
    ctx: &C,
    which_step: ShuffleStep,
) -> Result<Vec<I>, Error>
where
    C: Context,
    I: Reshare<C, RecordId> + Send + Sync,
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
/// Shuffle calls `shuffle_once` three times with 2 helpers shuffling the shares each time.
/// Order of calling `shuffle_once` is shuffle with (H2, H3), (H3, H1) and (H1, H2).
/// Each shuffle requires communication between helpers to perform reshare.
/// Infrastructure has a pre-requisite to distinguish each communication step uniquely.
/// For this, we have three shuffle steps one per `shuffle_once` i.e. Step1, Step2 and Step3.
/// The Shuffle object receives a step function and appends a `ShuffleStep` to form a concrete step
///
/// ![Shuffle steps][shuffle]
pub async fn shuffle_shares<C, I>(
    input: Vec<I>,
    random_permutations: (&[u32], &[u32]),
    ctx: C,
) -> Result<Vec<I>, Error>
where
    C: Context,
    I: Reshare<C, RecordId> + Send + Sync,
{
    let input = shuffle_once(
        input,
        random_permutations,
        ShuffleOrUnshuffle::Shuffle,
        &ctx,
        Shuffle1,
    )
    .await?;
    let input = shuffle_once(
        input,
        random_permutations,
        ShuffleOrUnshuffle::Shuffle,
        &ctx,
        Shuffle2,
    )
    .await?;
    shuffle_once(
        input,
        random_permutations,
        ShuffleOrUnshuffle::Shuffle,
        &ctx,
        Shuffle3,
    )
    .await
}

#[cfg(all(test, unit_test))]
mod tests {

    mod semi_honest {
        use std::collections::HashSet;

        use crate::{
            accumulation_test_input,
            ff::{Fp31, Fp32BitPrime},
            protocol::{
                attribution::input::AccumulateCreditInputRow,
                context::{Context, UpgradableContext, Validator},
                sort::{
                    apply_sort::shuffle::shuffle_shares,
                    shuffle::get_two_of_three_random_permutations,
                },
                BreakdownKey, MatchKey,
            },
            rand::{thread_rng, Rng},
            secret_sharing::{
                replicated::{semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing},
                BitDecomposed,
            },
            test_fixture::{
                bits_to_value, get_bits, input::GenericReportTestInput, Reconstruct, Runner,
                TestWorld,
            },
        };

        #[tokio::test]
        async fn shuffle_attribution_input_row() {
            const BATCHSIZE: u8 = 25;
            let world = TestWorld::default();
            let mut rng = thread_rng();

            let mut input: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> =
                Vec::with_capacity(BATCHSIZE.into());
            input.resize_with(BATCHSIZE.into(), || {
                accumulation_test_input!(
                    {
                        is_trigger_report: rng.gen::<u8>(),
                        helper_bit: rng.gen::<u8>(),
                        active_bit: rng.gen::<u8>(),
                        credit: rng.gen::<u8>(),
                    };
                    (Fp31, MatchKey, BreakdownKey)
                )
            });
            let hashed_input: HashSet<[u8; 3]> = input
                .iter()
                .map(|x| {
                    [
                        u8::from(x.is_trigger_report.unwrap()),
                        u8::from(x.helper_bit.unwrap()),
                        u8::from(x.trigger_value),
                    ]
                })
                .collect();

            let result: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> = world
                .semi_honest(
                    input.clone().into_iter(),
                    |ctx, shares: Vec<AccumulateCreditInputRow<Fp31, Replicated<_>>>| async move {
                        let validator = ctx.validator::<Fp31>(); // Just ignore this here.
                        let ctx = validator.context();

                        let perms =
                            get_two_of_three_random_permutations(BATCHSIZE.into(), ctx.prss_rng());

                        shuffle_shares(shares, (perms.0.as_slice(), perms.1.as_slice()), ctx)
                            .await
                            .unwrap()
                    },
                )
                .await
                .reconstruct();

            let mut hashed_output_secret = HashSet::new();
            let mut output_secret = Vec::new();
            for val in result {
                output_secret.push(val);
                hashed_output_secret.insert([
                    u8::from(val.is_trigger_report.unwrap()),
                    u8::from(val.helper_bit.unwrap()),
                    u8::from(val.trigger_value),
                ]);
            }

            // Secrets should be shuffled
            assert_ne!(output_secret, input);

            // Shuffled output should have same inputs
            assert_eq!(hashed_output_secret, hashed_input);
        }

        fn share_appears_anywhere(
            x: &Replicated<Fp32BitPrime>,
            inputs: &[BitDecomposed<Replicated<Fp32BitPrime>>],
        ) -> bool {
            inputs.iter().any(|row| {
                row.iter()
                    .any(|share| share.left() == x.left() && share.right() == x.right())
            })
        }

        #[tokio::test]
        async fn shuffle_vec_of_replicated() {
            const BIT_LENGTH: u32 = 32;
            let some_numbers = vec![
                123_456_789,
                234_567_890,
                345_678_901,
                456_789_012,
                567_890_123,
            ];
            let some_numbers_as_bits = some_numbers
                .iter()
                .map(|&x| get_bits::<Fp32BitPrime>(x, BIT_LENGTH))
                .collect::<Vec<_>>();
            let world = TestWorld::default();

            let result = world
                .semi_honest(some_numbers_as_bits.into_iter(), |ctx, shares| async move {
                    let copy_of_input = shares.clone();
                    let perms = get_two_of_three_random_permutations(5, ctx.prss_rng());
                    let shuffled_shares =
                        shuffle_shares(shares, (perms.0.as_slice(), perms.1.as_slice()), ctx)
                            .await
                            .unwrap();

                    assert!(!shuffled_shares.iter().any(|row| row
                        .iter()
                        .any(|x| share_appears_anywhere(x, &copy_of_input))));

                    shuffled_shares
                })
                .await
                .reconstruct();

            let mut reconstructed_inputs = result
                .iter()
                .map(|vec| u32::try_from(bits_to_value(vec)).unwrap())
                .collect::<Vec<_>>();
            reconstructed_inputs.sort_unstable();
            assert_eq!(reconstructed_inputs, some_numbers);
        }
    }
}
