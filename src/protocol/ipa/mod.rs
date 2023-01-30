use std::iter::{repeat, zip};

use crate::{
    bits::BitArray,
    error::Error,
    ff::Field,
    helpers::Role,
    protocol::{
        attribution::{
            accumulate_credit::accumulate_credit, aggregate_credit::aggregate_credit,
            credit_capping::credit_capping, AttributionInputRow,
        },
        context::Context,
        sort::{
            apply_sort::apply_sort_permutation,
            generate_permutation::generate_permutation_and_reveal_shuffled,
        },
        RecordId,
    },
    secret_sharing::replicated::semi_honest::{
        AdditiveShare as Replicated, XorShare as XorReplicated,
    },
};
use async_trait::async_trait;
use futures::future::{try_join, try_join_all};

use super::{attribution::AggregateCreditOutputRow, context::SemiHonestContext};
use super::{
    modulus_conversion::{combine_slices, convert_all_bits, convert_all_bits_local},
    sort::apply_sort::shuffle::Resharable,
    Substep,
};
use crate::protocol::boolean::bitwise_equal::bitwise_equal;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    ModulusConversionForMatchKeys,
    GenSortPermutationFromMatchKeys,
    ApplySortPermutation,
    ComputeHelperBits,
    AccumulateCredit,
    PerformUserCapping,
    AggregateCredit,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::ModulusConversionForMatchKeys => "mod_conv_match_key",
            Self::GenSortPermutationFromMatchKeys => "gen_sort_permutation_from_match_keys",
            Self::ApplySortPermutation => "apply_sort_permutation",
            Self::ComputeHelperBits => "compute_helper_bits",
            Self::AccumulateCredit => "accumulate_credit",
            Self::PerformUserCapping => "user_capping",
            Self::AggregateCredit => "aggregate_credit",
        }
    }
}
pub enum IPAInputRowResharableStep {
    MatchKeyShares,
    TriggerBit,
    BreakdownKey,
    TriggerValue,
}

impl Substep for IPAInputRowResharableStep {}

impl AsRef<str> for IPAInputRowResharableStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::MatchKeyShares => "match_key_shares",
            Self::TriggerBit => "is_trigger_bit",
            Self::BreakdownKey => "breakdown_key",
            Self::TriggerValue => "trigger_value",
        }
    }
}

pub struct IPAInputRow<F: Field, B: BitArray> {
    pub mk_shares: XorReplicated<B>,
    pub is_trigger_bit: Replicated<F>,
    pub breakdown_key: Replicated<F>,
    pub trigger_value: Replicated<F>,
}

struct IPAModulusConvertedInputRow<F: Field> {
    mk_shares: Vec<Replicated<F>>,
    is_trigger_bit: Replicated<F>,
    breakdown_key: Replicated<F>,
    trigger_value: Replicated<F>,
}

#[async_trait]
impl<F: Field + Sized> Resharable<F> for IPAModulusConvertedInputRow<F> {
    type Share = Replicated<F>;

    async fn reshare<C>(&self, ctx: C, record_id: RecordId, to_helper: Role) -> Result<Self, Error>
    where
        C: Context<F, Share = <Self as Resharable<F>>::Share> + Send,
    {
        let f_mk_shares = self.mk_shares.reshare(
            ctx.narrow(&IPAInputRowResharableStep::MatchKeyShares),
            record_id,
            to_helper,
        );
        let f_is_trigger_bit = ctx.narrow(&IPAInputRowResharableStep::TriggerBit).reshare(
            &self.is_trigger_bit,
            record_id,
            to_helper,
        );
        let f_breakdown_key = ctx
            .narrow(&IPAInputRowResharableStep::BreakdownKey)
            .reshare(&self.breakdown_key, record_id, to_helper);
        let f_trigger_value = ctx
            .narrow(&IPAInputRowResharableStep::TriggerValue)
            .reshare(&self.trigger_value, record_id, to_helper);

        let (mk_shares, mut outputs) = try_join(
            f_mk_shares,
            try_join_all([f_is_trigger_bit, f_breakdown_key, f_trigger_value]),
        )
        .await?;

        Ok(IPAModulusConvertedInputRow {
            mk_shares,
            is_trigger_bit: outputs.remove(0),
            breakdown_key: outputs.remove(0),
            trigger_value: outputs.remove(0),
        })
    }
}

/// # Errors
/// Propagates errors from multiplications
/// # Panics
/// Propagates errors from multiplications
#[allow(dead_code)]
pub async fn ipa<F, B>(
    ctx: SemiHonestContext<'_, F>,
    input_rows: &[IPAInputRow<F, B>],
    per_user_credit_cap: u32,
    max_breakdown_key: u128,
    num_multi_bits: u32,
) -> Result<Vec<AggregateCreditOutputRow<F>>, Error>
where
    F: Field,
    B: BitArray,
{
    let mk_shares = input_rows
        .iter()
        .map(|x| x.mk_shares.clone())
        .collect::<Vec<_>>();
    let local_lists = convert_all_bits_local(ctx.role(), &mk_shares, B::BITS);
    let converted_shares = convert_all_bits(
        &ctx.narrow(&Step::ModulusConversionForMatchKeys),
        local_lists,
        B::BITS,
        num_multi_bits,
    )
    .await
    .unwrap();
    let converted_shares = converted_shares.collect::<Vec<_>>();
    let sort_permutation = generate_permutation_and_reveal_shuffled(
        ctx.narrow(&Step::GenSortPermutationFromMatchKeys),
        &converted_shares,
    )
    .await
    .unwrap();
    let converted_shares = combine_slices(&converted_shares, B::BITS);

    let combined_match_keys_and_sidecar_data = input_rows
        .iter()
        .zip(converted_shares)
        .map(|(input_row, mk_shares)| IPAModulusConvertedInputRow {
            mk_shares,
            is_trigger_bit: input_row.is_trigger_bit.clone(),
            breakdown_key: input_row.breakdown_key.clone(),
            trigger_value: input_row.trigger_value.clone(),
        })
        .collect::<Vec<_>>();

    let sorted_rows = apply_sort_permutation(
        ctx.narrow(&Step::ApplySortPermutation),
        combined_match_keys_and_sidecar_data,
        &sort_permutation,
    )
    .await
    .unwrap();

    let futures = zip(
        repeat(
            ctx.narrow(&Step::ComputeHelperBits)
                .set_total_records(sorted_rows.len() - 1),
        ),
        sorted_rows.iter(),
    )
    .zip(sorted_rows.iter().skip(1))
    .enumerate()
    .map(|(i, ((ctx, row), next_row))| {
        let record_id = RecordId::from(i);
        async move { bitwise_equal(ctx, record_id, &row.mk_shares, &next_row.mk_shares).await }
    });
    let helper_bits = Some(Replicated::ZERO)
        .into_iter()
        .chain(try_join_all(futures).await?);

    let attribution_input_rows = zip(sorted_rows, helper_bits)
        .map(|(row, hb)| AttributionInputRow {
            is_trigger_bit: row.is_trigger_bit,
            helper_bit: hb,
            breakdown_key: row.breakdown_key,
            credit: row.trigger_value,
        })
        .collect::<Vec<_>>();

    let accumulated_credits =
        accumulate_credit(ctx.narrow(&Step::AccumulateCredit), &attribution_input_rows).await?;

    let user_capped_credits = credit_capping(
        ctx.narrow(&Step::PerformUserCapping),
        &accumulated_credits,
        per_user_credit_cap,
    )
    .await?;

    aggregate_credit(
        ctx.narrow(&Step::AggregateCredit),
        &user_capped_credits,
        max_breakdown_key,
        num_multi_bits,
    )
    .await
}

#[cfg(all(test, not(feature = "shuttle")))]
pub mod tests {
    use super::ipa;
    use crate::bits::BitArray40;
    use crate::test_fixture::ipa_input_row::IPAInputTestRow;
    use crate::{ff::Fp32BitPrime, rand::thread_rng};
    use crate::{
        ff::{Field, Fp31},
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    #[allow(clippy::missing_panics_doc)]
    pub async fn semi_honest() {
        const COUNT: usize = 5;
        const PER_USER_CAP: u32 = 3;
        const EXPECTED: &[[u128; 2]] = &[[0, 0], [1, 2], [2, 3]];
        const MAX_BREAKDOWN_KEY: u128 = 3;
        const NUM_MULTI_BITS: u32 = 3;

        let world = TestWorld::new().await;

        //   match key, is_trigger, breakdown_key, trigger_value
        let records = [
            IPAInputTestRow {
                match_key: 12345,
                is_trigger_bit: 0,
                breakdown_key: 1,
                trigger_value: 0,
            },
            IPAInputTestRow {
                match_key: 12345,
                is_trigger_bit: 0,
                breakdown_key: 2,
                trigger_value: 0,
            },
            IPAInputTestRow {
                match_key: 68362,
                is_trigger_bit: 0,
                breakdown_key: 1,
                trigger_value: 0,
            },
            IPAInputTestRow {
                match_key: 12345,
                is_trigger_bit: 1,
                breakdown_key: 0,
                trigger_value: 5,
            },
            IPAInputTestRow {
                match_key: 68362,
                is_trigger_bit: 1,
                breakdown_key: 0,
                trigger_value: 2,
            },
        ];

        let result = world
            .semi_honest(records, |ctx, input_rows| async move {
                ipa::<Fp31, BitArray40>(
                    ctx,
                    &input_rows,
                    PER_USER_CAP,
                    MAX_BREAKDOWN_KEY,
                    NUM_MULTI_BITS,
                )
                .await
                .unwrap()
            })
            .await
            .reconstruct();

        assert_eq!(EXPECTED.len(), result.len());

        for (i, expected) in EXPECTED.iter().enumerate() {
            // Each element in the `result` is a general purpose `[F; 4]`.
            // For this test case, the first two elements are `breakdown_key`
            // and `credit` as defined by the implementation of `Reconstruct`
            // for `[AggregateCreditOutputRow<F>; 3]`.
            let result = result[i].0.map(|x| x.as_u128());
            assert_eq!(*expected, [result[0], result[1]]);
        }
    }

    #[tokio::test]
    #[allow(clippy::missing_panics_doc)]
    #[ignore]
    pub async fn random_ipa_no_result_check() {
        const BATCHSIZE: u64 = 20;
        const PER_USER_CAP: u32 = 10;
        const MAX_BREAKDOWN_KEY: u128 = 8;
        const MAX_TRIGGER_VALUE: u128 = 5;
        const NUM_MULTI_BITS: u32 = 3;

        let max_match_key: u64 = BATCHSIZE / 10;

        let world = TestWorld::new().await;
        let mut rng = thread_rng();

        let mut records: Vec<IPAInputTestRow> = Vec::new();

        for _ in 0..BATCHSIZE {
            records.push(IPAInputTestRow::random(
                &mut rng,
                max_match_key,
                MAX_BREAKDOWN_KEY,
                MAX_TRIGGER_VALUE,
            ));
        }
        let result = world
            .semi_honest(records, |ctx, input_rows| async move {
                ipa::<Fp32BitPrime, BitArray40>(
                    ctx,
                    &input_rows,
                    PER_USER_CAP,
                    MAX_BREAKDOWN_KEY,
                    NUM_MULTI_BITS,
                )
                .await
                .unwrap()
            })
            .await
            .reconstruct();

        assert_eq!(MAX_BREAKDOWN_KEY, result.len() as u128);
    }
}
