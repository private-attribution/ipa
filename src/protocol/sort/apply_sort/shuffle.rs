use std::iter::{repeat, zip};

use crate::repeat64str;
use crate::secret_sharing::Arithmetic;
use crate::secret_sharing::{ArithmeticShare, SecretSharing};
use crate::{
    error::Error,
    ff::Field,
    helpers::{Direction, Role},
    protocol::{context::Context, RecordId},
};
use async_trait::async_trait;
use embed_doc_image::embed_doc_image;
use futures::future::try_join_all;

use crate::protocol::sort::shuffle::{shuffle_for_helper, ShuffleOrUnshuffle};
use crate::protocol::sort::{
    apply::{apply, apply_inv},
    ShuffleStep::{self, Step1, Step2, Step3},
};

#[async_trait]
pub trait Resharable<V: ArithmeticShare>: Sized {
    type Share: SecretSharing<V>;

    async fn reshare<C>(&self, ctx: C, record_id: RecordId, to_helper: Role) -> Result<Self, Error>
    where
        C: Context<V, Share = <Self as Resharable<V>>::Share> + Send;
}

pub struct InnerVectorElementStep(usize);

impl crate::protocol::Substep for InnerVectorElementStep {}

impl AsRef<str> for InnerVectorElementStep {
    fn as_ref(&self) -> &str {
        const VEC_ELEM: [&str; 64] = repeat64str!["elem"];
        VEC_ELEM[self.0]
    }
}

impl From<usize> for InnerVectorElementStep {
    fn from(v: usize) -> Self {
        Self(v)
    }
}

#[async_trait]
impl<T: Arithmetic<F>, F: Field> Resharable<F> for Vec<T> {
    type Share = T;

    /// This is intended to be used for resharing vectors of bit-decomposed values.
    /// # Errors
    /// If the vector has more than 64 elements
    async fn reshare<C>(&self, ctx: C, record_id: RecordId, to_helper: Role) -> Result<Self, Error>
    where
        C: Context<F, Share = <Self as Resharable<F>>::Share> + Send,
    {
        try_join_all(self.iter().enumerate().map(|(i, x)| {
            let c = ctx.narrow(&InnerVectorElementStep::from(i));
            async move { c.reshare(x, record_id, to_helper).await }
        }))
        .await
    }
}

async fn reshare<F, C, S, T>(input: &[T], ctx: C, to_helper: Role) -> Result<Vec<T>, Error>
where
    C: Context<F, Share = S> + Send,
    F: Field,
    S: SecretSharing<F>,
    T: Resharable<F, Share = S>,
{
    let ctx = ctx.set_total_records(input.len());
    let reshares = zip(repeat(ctx), input)
        .enumerate()
        .map(|(index, (ctx, input))| async move {
            input.reshare(ctx, RecordId::from(index), to_helper).await
        });
    try_join_all(reshares).await
}

/// `shuffle_once` is called for the helpers
/// i)   2 helpers receive permutation pair and choose the permutation to be applied
/// ii)  2 helpers apply the permutation to their shares
/// iii) reshare to `to_helper`
async fn shuffle_once<F, S, C, I>(
    mut input: Vec<I>,
    random_permutations: (&[u32], &[u32]),
    shuffle_or_unshuffle: ShuffleOrUnshuffle,
    ctx: &C,
    which_step: ShuffleStep,
) -> Result<Vec<I>, Error>
where
    C: Context<F, Share = S> + Send,
    F: Field,
    I: Resharable<F, Share = S>,
    S: SecretSharing<F>,
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
    reshare(&input, ctx, to_helper).await
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
pub async fn shuffle_shares<C, F, I, S>(
    input: Vec<I>,
    random_permutations: (&[u32], &[u32]),
    ctx: C,
) -> Result<Vec<I>, Error>
where
    C: Context<F, Share = S> + Send,
    F: Field,
    I: Resharable<F, Share = S>,
    S: SecretSharing<F>,
{
    let input = shuffle_once(
        input,
        random_permutations,
        ShuffleOrUnshuffle::Shuffle,
        &ctx,
        Step1,
    )
    .await?;
    let input = shuffle_once(
        input,
        random_permutations,
        ShuffleOrUnshuffle::Shuffle,
        &ctx,
        Step2,
    )
    .await?;
    shuffle_once(
        input,
        random_permutations,
        ShuffleOrUnshuffle::Shuffle,
        &ctx,
        Step3,
    )
    .await
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {

    mod semi_honest {
        use crate::accumulation_test_input;
        use crate::bits::BitArray;
        use crate::protocol::attribution::input::{
            AccumulateCreditInputRow, MCAccumulateCreditInputRow,
        };
        use crate::protocol::modulus_conversion::{
            combine_slices, convert_all_bits, convert_all_bits_local,
        };
        use crate::protocol::{BreakdownKey, MatchKey};
        use crate::rand::{thread_rng, Rng};

        use crate::ff::{Fp31, Fp32BitPrime};
        use crate::protocol::context::Context;
        use crate::protocol::sort::apply_sort::shuffle::shuffle_shares;
        use crate::protocol::sort::shuffle::get_two_of_three_random_permutations;
        use crate::secret_sharing::replicated::semi_honest::AdditiveShare as Replicated;
        use crate::secret_sharing::SharedValue;
        use crate::test_fixture::input::GenericReportTestInput;
        use crate::test_fixture::{bits_to_value, get_bits, Reconstruct, Runner, TestWorld};
        use std::collections::HashSet;
        use std::marker::PhantomData;

        #[tokio::test]
        async fn shuffle_attribution_input_row() {
            const NUM_MULTI_BITS: u32 = 3;
            const BATCHSIZE: u8 = 25;
            let world = TestWorld::new().await;
            let mut rng = thread_rng();

            let mut input: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> =
                Vec::with_capacity(BATCHSIZE.into());
            input.resize_with(BATCHSIZE.into(), || {
                accumulation_test_input!(
                    {
                        is_trigger_report: rng.gen::<u8>(),
                        helper_bit: rng.gen::<u8>(),
                        breakdown_key: rng.gen::<u8>(),
                        credit: rng.gen::<u8>(),
                    };
                    (Fp31, MatchKey, BreakdownKey)
                )
            });
            let hashed_input: HashSet<[u8; 4]> = input
                .iter()
                .map(|x| {
                    [
                        u8::from(x.is_trigger_report.unwrap()),
                        u8::from(x.helper_bit.unwrap()),
                        u8::try_from(x.breakdown_key.as_u128()).unwrap(),
                        u8::from(x.trigger_value),
                    ]
                })
                .collect();

            let result: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> = world
                .semi_honest(
                    input.clone(),
                    |ctx, shares: Vec<AccumulateCreditInputRow<Fp31, BreakdownKey>>| async move {
                        let perms =
                            get_two_of_three_random_permutations(BATCHSIZE.into(), ctx.prss_rng());

                        let bk_shares = shares
                            .iter()
                            .map(|x| x.breakdown_key.clone())
                            .collect::<Vec<_>>();
                        let converted_bk_shares = convert_all_bits(
                            &ctx,
                            &convert_all_bits_local(ctx.role(), &bk_shares),
                            BreakdownKey::BITS,
                            NUM_MULTI_BITS,
                        )
                        .await
                        .unwrap();
                        let converted_bk_shares = combine_slices(
                            converted_bk_shares.iter(),
                            BATCHSIZE.into(),
                            BreakdownKey::BITS,
                        );

                        let converted_shares = shares
                            .into_iter()
                            .zip(converted_bk_shares)
                            .map(|(row, bk)| MCAccumulateCreditInputRow {
                                is_trigger_report: row.is_trigger_report,
                                helper_bit: row.helper_bit,
                                breakdown_key: bk,
                                trigger_value: row.trigger_value,
                                _marker: PhantomData::default(),
                            })
                            .collect::<Vec<_>>();

                        shuffle_shares(
                            converted_shares,
                            (perms.0.as_slice(), perms.1.as_slice()),
                            ctx,
                        )
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
                    u8::try_from(val.breakdown_key.as_u128()).unwrap(),
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
            inputs: &[Vec<Replicated<Fp32BitPrime>>],
        ) -> bool {
            inputs.iter().any(|row| {
                row.iter()
                    .any(|share| share.left() == x.left() && share.right() == x.right())
            })
        }

        #[tokio::test]
        async fn shuffle_vec_of_replicated() {
            const BIT_LENGTH: u32 = 32;
            let some_numbers = [
                123_456_789,
                234_567_890,
                345_678_901,
                456_789_012,
                567_890_123,
            ];
            let some_numbers_as_bits =
                some_numbers.map(|x| get_bits::<Fp32BitPrime>(x, BIT_LENGTH));
            let world = TestWorld::new().await;

            let result = world
                .semi_honest(
                    some_numbers_as_bits,
                    |ctx, vec_of_vec_of_shares| async move {
                        let copy_of_input = vec_of_vec_of_shares.clone();

                        let perms = get_two_of_three_random_permutations(5, ctx.prss_rng());
                        let shuffled_shares = shuffle_shares(
                            vec_of_vec_of_shares,
                            (perms.0.as_slice(), perms.1.as_slice()),
                            ctx,
                        )
                        .await
                        .unwrap();

                        assert!(!shuffled_shares.iter().any(|row| row
                            .iter()
                            .any(|x| share_appears_anywhere(x, &copy_of_input))));

                        shuffled_shares
                    },
                )
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
