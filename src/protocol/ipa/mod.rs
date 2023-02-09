use std::{
    iter::{repeat, zip},
    marker::PhantomData,
};

use crate::{
    bits::BitArray,
    error::Error,
    ff::Field,
    helpers::Role,
    protocol::{
        attribution::{
            accumulate_credit::accumulate_credit, aggregate_credit::aggregate_credit,
            credit_capping::credit_capping,
        },
        context::Context,
        sort::apply_sort::apply_sort_permutation,
        RecordId,
    },
    secret_sharing::{
        replicated::malicious::AdditiveShare as MaliciousReplicated,
        replicated::semi_honest::{AdditiveShare as Replicated, XorShare as XorReplicated},
        Arithmetic,
    },
};

use async_trait::async_trait;
use futures::future::{try_join3, try_join_all};

use super::{
    attribution::{
        aggregate_credit::malicious_aggregate_credit,
        input::{MCAccumulateCreditInputRow, MCAggregateCreditOutputRow},
    },
    context::{malicious::IPAModulusConvertedInputRowWrapper, SemiHonestContext},
    malicious::MaliciousValidator,
    sort::generate_permutation::{
        generate_permutation_and_reveal_shuffled,
        malicious_generate_permutation_and_reveal_shuffled,
    },
};
use super::{
    modulus_conversion::{combine_slices, convert_all_bits, convert_all_bits_local},
    sort::apply_sort::shuffle::Resharable,
    Substep,
};
use crate::protocol::boolean::bitwise_equal::bitwise_equal;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    ModulusConversionForMatchKeys,
    ModulusConversionForBreakdownKeys,
    GenSortPermutationFromMatchKeys,
    ApplySortPermutation,
    ComputeHelperBits,
    AccumulateCredit,
    PerformUserCapping,
    AggregateCredit,
    AfterConvertAllBits,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::ModulusConversionForMatchKeys => "mod_conv_match_key",
            Self::ModulusConversionForBreakdownKeys => "mod_conv_breakdown_key",
            Self::GenSortPermutationFromMatchKeys => "gen_sort_permutation_from_match_keys",
            Self::ApplySortPermutation => "apply_sort_permutation",
            Self::ComputeHelperBits => "compute_helper_bits",
            Self::AccumulateCredit => "accumulate_credit",
            Self::PerformUserCapping => "user_capping",
            Self::AggregateCredit => "aggregate_credit",
            Self::AfterConvertAllBits => "after_convert_all_bits",
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

pub struct IPAInputRow<F: Field, MK: BitArray, BK: BitArray> {
    pub mk_shares: XorReplicated<MK>,
    pub is_trigger_bit: Replicated<F>,
    pub breakdown_key: XorReplicated<BK>,
    pub trigger_value: Replicated<F>,
}

pub struct IPAModulusConvertedInputRow<F: Field, T: Arithmetic<F>> {
    pub mk_shares: Vec<T>,
    pub is_trigger_bit: T,
    pub breakdown_key: Vec<T>,
    pub trigger_value: T,
    pub _marker: PhantomData<F>,
}

#[async_trait]
impl<F: Field + Sized, T: Arithmetic<F>> Resharable<F> for IPAModulusConvertedInputRow<F, T> {
    type Share = T;

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
        let f_breakdown_key = self.breakdown_key.reshare(
            ctx.narrow(&IPAInputRowResharableStep::BreakdownKey),
            record_id,
            to_helper,
        );
        let f_trigger_value = ctx
            .narrow(&IPAInputRowResharableStep::TriggerValue)
            .reshare(&self.trigger_value, record_id, to_helper);

        let (mk_shares, breakdown_key, mut outputs) = try_join3(
            f_mk_shares,
            f_breakdown_key,
            try_join_all([f_is_trigger_bit, f_trigger_value]),
        )
        .await?;

        Ok(IPAModulusConvertedInputRow {
            mk_shares,
            breakdown_key,
            is_trigger_bit: outputs.remove(0),
            trigger_value: outputs.remove(0),
            _marker: PhantomData::default(),
        })
    }
}

/// # Errors
/// Propagates errors from multiplications
/// # Panics
/// Propagates errors from multiplications
#[allow(dead_code)]
pub async fn ipa<F, MK, BK>(
    ctx: SemiHonestContext<'_, F>,
    input_rows: &[IPAInputRow<F, MK, BK>],
    per_user_credit_cap: u32,
    max_breakdown_key: u128,
    num_multi_bits: u32,
) -> Result<Vec<MCAggregateCreditOutputRow<F, Replicated<F>>>, Error>
where
    F: Field,
    MK: BitArray,
    BK: BitArray,
{
    let num_records = input_rows.len();
    let (mk_shares, bk_shares): (Vec<_>, Vec<_>) = input_rows
        .iter()
        .map(|x| (x.mk_shares.clone(), x.breakdown_key.clone()))
        .unzip();

    // Breakdown key modulus conversion
    let converted_bk_shares = convert_all_bits(
        &ctx.narrow(&Step::ModulusConversionForBreakdownKeys),
        &convert_all_bits_local(ctx.role(), &bk_shares),
        BK::BITS,
        num_multi_bits,
    )
    .await
    .unwrap();
    let converted_bk_shares = combine_slices(converted_bk_shares.iter(), num_records, BK::BITS);

    // Match key modulus conversion, and then sort
    let converted_mk_shares = convert_all_bits(
        &ctx.narrow(&Step::ModulusConversionForMatchKeys),
        &convert_all_bits_local(ctx.role(), &mk_shares),
        MK::BITS,
        num_multi_bits,
    )
    .await
    .unwrap();

    let sort_permutation = generate_permutation_and_reveal_shuffled(
        ctx.narrow(&Step::GenSortPermutationFromMatchKeys),
        converted_mk_shares.iter(),
    )
    .await
    .unwrap();

    let converted_mk_shares = combine_slices(converted_mk_shares.iter(), num_records, MK::BITS);

    let combined_match_keys_and_sidecar_data =
        std::iter::zip(converted_mk_shares, converted_bk_shares)
            .into_iter()
            .zip(input_rows)
            .map(
                |((mk_shares, bk_shares), input_row)| IPAModulusConvertedInputRow {
                    mk_shares,
                    is_trigger_bit: input_row.is_trigger_bit.clone(),
                    breakdown_key: bk_shares,
                    trigger_value: input_row.trigger_value.clone(),
                    _marker: PhantomData::default(),
                },
            )
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
        .map(|(row, hb)| MCAccumulateCreditInputRow {
            is_trigger_report: row.is_trigger_bit,
            helper_bit: hb,
            breakdown_key: row.breakdown_key,
            trigger_value: row.trigger_value,
            _marker: PhantomData::default(),
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

    aggregate_credit::<F, BK>(
        ctx.narrow(&Step::AggregateCredit),
        &user_capped_credits,
        max_breakdown_key,
        num_multi_bits,
    )
    .await
}

/// Malicious IPA
/// We return Replicated<F> as output since there is compute after this and in `aggregate_credit`, last communication operation was sort
/// # Errors
/// Propagates errors from multiplications
/// # Panics
/// Propagates errors from multiplications
#[allow(dead_code, clippy::too_many_lines)]
pub async fn ipa_wip_malicious<F, MK, BK>(
    sh_ctx: SemiHonestContext<'_, F>,
    input_rows: &[IPAInputRow<F, MK, BK>],
    per_user_credit_cap: u32,
    max_breakdown_key: u128,
    num_multi_bits: u32,
) -> Result<Vec<MCAggregateCreditOutputRow<F, MaliciousReplicated<F>>>, Error>
where
    F: Field,
    MK: BitArray,
    BK: BitArray,
{
    let num_records = input_rows.len();
    let malicious_validator = MaliciousValidator::new(sh_ctx.clone());
    let m_ctx = malicious_validator.context();

    let (mk_shares, bk_shares): (Vec<_>, Vec<_>) = input_rows
        .iter()
        .map(|x| (x.mk_shares.clone(), x.breakdown_key.clone()))
        .unzip();

    // Match key modulus conversion, and then sort
    let converted_mk_shares = convert_all_bits(
        &m_ctx.narrow(&Step::ModulusConversionForMatchKeys),
        &m_ctx
            .upgrade(convert_all_bits_local(m_ctx.role(), &mk_shares))
            .await?,
        MK::BITS,
        num_multi_bits,
    )
    .await
    .unwrap();

    //Validate before calling sort with downgraded context
    let converted_mk_shares = malicious_validator.validate(converted_mk_shares).await?;

    let sort_permutation = malicious_generate_permutation_and_reveal_shuffled(
        sh_ctx.narrow(&Step::GenSortPermutationFromMatchKeys),
        converted_mk_shares.iter(),
    )
    .await
    .unwrap();

    let malicious_validator = MaliciousValidator::new(sh_ctx.narrow(&Step::AfterConvertAllBits));
    let m_ctx = malicious_validator.context();

    let converted_mk_shares = combine_slices(converted_mk_shares.iter(), num_records, MK::BITS);

    // Breakdown key modulus conversion
    let converted_bk_shares = convert_all_bits(
        &m_ctx.narrow(&Step::ModulusConversionForBreakdownKeys),
        &m_ctx
            .narrow(&Step::ModulusConversionForBreakdownKeys)
            .upgrade(convert_all_bits_local(m_ctx.role(), &bk_shares))
            .await?,
        BK::BITS,
        num_multi_bits,
    )
    .await
    .unwrap();

    let converted_bk_shares = combine_slices(converted_bk_shares.iter(), num_records, BK::BITS);

    let intermediate = converted_mk_shares
        .into_iter()
        .zip(input_rows)
        .map(
            |(mk_shares, input_row)| IPAModulusConvertedInputRowWrapper {
                mk_shares,
                is_trigger_bit: input_row.is_trigger_bit.clone(),
                trigger_value: input_row.trigger_value.clone(),
                _marker: PhantomData::default(),
            },
        )
        .collect::<Vec<_>>();

    let intermediate = m_ctx.upgrade(intermediate).await?;

    let combined_match_keys_and_sidecar_data = intermediate
        .into_iter()
        .zip(converted_bk_shares)
        .map(
            |(one_row, bk_shares)| IPAModulusConvertedInputRow::<F, MaliciousReplicated<F>> {
                mk_shares: one_row.mk_shares,
                is_trigger_bit: one_row.is_trigger_bit,
                trigger_value: one_row.trigger_value,
                breakdown_key: bk_shares,
                _marker: PhantomData::default(),
            },
        )
        .collect::<Vec<_>>();

    let sorted_rows = apply_sort_permutation(
        m_ctx.narrow(&Step::ApplySortPermutation),
        combined_match_keys_and_sidecar_data,
        &sort_permutation,
    )
    .await
    .unwrap();

    let futures = zip(
        repeat(
            m_ctx
                .narrow(&Step::ComputeHelperBits)
                .set_total_records(sorted_rows.len() - 1),
        ),
        sorted_rows.iter(),
    )
    .zip(sorted_rows.iter().skip(1))
    .enumerate()
    .map(|(i, ((m_ctx, row), next_row))| {
        let record_id = RecordId::from(i);
        async move { bitwise_equal(m_ctx, record_id, &row.mk_shares, &next_row.mk_shares).await }
    });
    let helper_bits = Some(MaliciousReplicated::ZERO)
        .into_iter()
        .chain(try_join_all(futures).await?);

    let attribution_input_rows = zip(sorted_rows, helper_bits)
        .map(|(row, hb)| MCAccumulateCreditInputRow {
            is_trigger_report: row.is_trigger_bit,
            helper_bit: hb,
            breakdown_key: row.breakdown_key,
            trigger_value: row.trigger_value,
            _marker: PhantomData::default(),
        })
        .collect::<Vec<_>>();

    let accumulated_credits = accumulate_credit(
        m_ctx.narrow(&Step::AccumulateCredit),
        &attribution_input_rows,
    )
    .await?;

    let user_capped_credits = credit_capping(
        m_ctx.narrow(&Step::PerformUserCapping),
        &accumulated_credits,
        per_user_credit_cap,
    )
    .await?;

    //Validate before calling sort with downgraded context
    malicious_aggregate_credit::<F, BK>(
        m_ctx.narrow(&Step::AggregateCredit),
        malicious_validator,
        sh_ctx,
        &user_capped_credits,
        max_breakdown_key,
        num_multi_bits,
    )
    .await
}

#[cfg(all(test, not(feature = "shuttle")))]
pub mod tests {
    use super::{ipa, ipa_wip_malicious};
    use crate::bits::BitArray;
    use crate::ipa_test_input;
    use crate::protocol::{BreakdownKey, MatchKey};
    use crate::telemetry::metrics::RECORDS_SENT;
    use crate::test_fixture::input::GenericReportTestInput;
    use crate::test_fixture::TestWorldConfig;
    use crate::{ff::Fp32BitPrime, rand::thread_rng};
    use crate::{
        ff::{Field, Fp31},
        test_fixture::{Reconstruct, Runner, TestWorld},
    };
    use rand::Rng;

    #[tokio::test]
    #[allow(clippy::missing_panics_doc)]
    pub async fn semi_honest() {
        const COUNT: usize = 5;
        const PER_USER_CAP: u32 = 3;
        const EXPECTED: &[[u128; 2]] = &[[0, 0], [1, 2], [2, 3]];
        const MAX_BREAKDOWN_KEY: u128 = 3;
        const NUM_MULTI_BITS: u32 = 3;

        let world = TestWorld::new().await;

        let records: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> = ipa_test_input!(
            [
                { match_key: 12345, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { match_key: 12345, is_trigger_report: 0, breakdown_key: 2, trigger_value: 0 },
                { match_key: 68362, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 5 },
                { match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 2 },
            ];
            (Fp31, MatchKey, BreakdownKey)
        );

        let result: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> = world
            .semi_honest(records, |ctx, input_rows| async move {
                ipa::<Fp31, MatchKey, BreakdownKey>(
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
            assert_eq!(
                *expected,
                [
                    result[i].breakdown_key.as_u128(),
                    result[i].trigger_value.as_u128()
                ]
            );
        }
    }

    #[tokio::test]
    async fn malicious() {
        const COUNT: usize = 5;
        const PER_USER_CAP: u32 = 3;
        const EXPECTED: &[[u128; 2]] = &[[0, 0], [1, 2], [2, 3]];
        const MAX_BREAKDOWN_KEY: u128 = 3;
        const NUM_MULTI_BITS: u32 = 3;

        let world = TestWorld::new().await;

        let records: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> = ipa_test_input!(
            [
                { match_key: 12345, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { match_key: 12345, is_trigger_report: 0, breakdown_key: 2, trigger_value: 0 },
                { match_key: 68362, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 5 },
                { match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 2 },
            ];
            (Fp31, MatchKey, BreakdownKey)
        );

        let [result0, result1, result2] = world
            .semi_honest(records, |ctx, input_rows| async move {
                ipa_wip_malicious::<Fp31, MatchKey, BreakdownKey>(
                    ctx,
                    &input_rows,
                    PER_USER_CAP,
                    MAX_BREAKDOWN_KEY,
                    NUM_MULTI_BITS,
                )
                .await
                .unwrap()
            })
            .await;

        assert_eq!(EXPECTED.len(), result0.len());
        assert_eq!(EXPECTED.len(), result1.len());
        assert_eq!(EXPECTED.len(), result2.len());
    }

    #[tokio::test]
    #[allow(clippy::missing_panics_doc)]
    #[ignore]
    pub async fn random_ipa_no_result_check() {
        const BATCHSIZE: u128 = 20;
        const PER_USER_CAP: u32 = 10;
        const MAX_BREAKDOWN_KEY: u128 = 8;
        const MAX_TRIGGER_VALUE: u128 = 5;
        const NUM_MULTI_BITS: u32 = 3;

        let max_match_key: u128 = BATCHSIZE / 10;

        let world = TestWorld::new().await;
        let mut rng = thread_rng();

        let mut records = Vec::new();

        for _ in 0..BATCHSIZE {
            records.push(ipa_test_input!(
                {
                    match_key: rng.gen_range(0..max_match_key),
                    is_trigger_report: rng.gen::<u32>(),
                    breakdown_key: rng.gen_range(0..MAX_BREAKDOWN_KEY),
                    trigger_value: rng.gen_range(0..MAX_TRIGGER_VALUE),
                };
                (Fp32BitPrime, MatchKey, BreakdownKey)
            ));
        }
        let result: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = world
            .semi_honest(records, |ctx, input_rows| async move {
                ipa::<Fp32BitPrime, MatchKey, BreakdownKey>(
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

    /// Ensures that our communication numbers don't go above the baseline.
    /// Prints a warning if they are currently below, so someone needs to adjust the baseline
    /// inside this test.
    ///
    /// It is possible to increase the number too if there is a good reason for it. This is a
    /// "catch all" type of test to make sure we don't miss an accidental regression.
    #[tokio::test]
    pub async fn communication_baseline() {
        const COUNT: usize = 5;
        const PER_USER_CAP: u32 = 3;
        const EXPECTED: &[[u128; 2]] = &[[0, 0], [1, 2], [2, 3]];
        const MAX_BREAKDOWN_KEY: u128 = 3;
        const NUM_MULTI_BITS: u32 = 3;

        /// empirical value as of Feb 4, 2023.
        const RECORDS_SENT_SEMI_HONEST_BASELINE: u64 = 10740;

        /// empirical value as of Feb 4, 2023.
        const RECORDS_SENT_MALICIOUS_BASELINE: u64 = 26395;

        let world = TestWorld::new_with(*TestWorldConfig::default().enable_metrics()).await;

        let records: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = ipa_test_input!(
            [
                { match_key: 12345, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { match_key: 12345, is_trigger_report: 0, breakdown_key: 2, trigger_value: 0 },
                { match_key: 68362, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 5 },
                { match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 2 },
            ];
            (Fp32BitPrime, MatchKey, BreakdownKey)
        );

        let _: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = world
            .semi_honest(records.clone(), |ctx, input_rows| async move {
                ipa::<Fp32BitPrime, MatchKey, BreakdownKey>(
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

        let snapshot = world.metrics_snapshot();
        let records_sent = snapshot.get_counter(RECORDS_SENT);
        assert!(records_sent <= RECORDS_SENT_SEMI_HONEST_BASELINE);
        if records_sent < RECORDS_SENT_SEMI_HONEST_BASELINE {
            tracing::warn!("Baseline for semi-honest IPA has improved! Expected {RECORDS_SENT_SEMI_HONEST_BASELINE}, got {records_sent}.\
                            Strongly consider adjusting the baseline, so the gains won't be accidentally offset by a regression.");
        }

        let world = TestWorld::new_with(*TestWorldConfig::default().enable_metrics()).await;

        let _ = world
            .semi_honest(records, |ctx, input_rows| async move {
                ipa_wip_malicious::<Fp32BitPrime, MatchKey, BreakdownKey>(
                    ctx,
                    &input_rows,
                    PER_USER_CAP,
                    MAX_BREAKDOWN_KEY,
                    NUM_MULTI_BITS,
                )
                .await
                .unwrap()
            })
            .await;

        let snapshot = world.metrics_snapshot();
        let records_sent = snapshot.get_counter(RECORDS_SENT);
        assert!(records_sent <= RECORDS_SENT_MALICIOUS_BASELINE);
        if records_sent < RECORDS_SENT_MALICIOUS_BASELINE {
            tracing::warn!("Baseline for malicious IPA has improved! Expected {RECORDS_SENT_MALICIOUS_BASELINE}, got {records_sent}.\
                            Strongly consider adjusting the baseline, so the gains won't be accidentally offset by a regression.");
        }
    }
}
