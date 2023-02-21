use crate::{
    bits::{Fp2Array, Serializable},
    error::Error,
    ff::Field,
    helpers::Role,
    protocol::{
        attribution::{
            accumulate_credit::accumulate_credit,
            aggregate_credit::{aggregate_credit, malicious_aggregate_credit},
            credit_capping::credit_capping,
            input::{MCAccumulateCreditInputRow, MCAggregateCreditOutputRow},
        },
        boolean::bitwise_equal::bitwise_equal,
        context::{malicious::IPAModulusConvertedInputRowWrapper, Context, SemiHonestContext},
        malicious::MaliciousValidator,
        modulus_conversion::{combine_slices, convert_all_bits, convert_all_bits_local},
        sort::{
            apply_sort::{apply_sort_permutation, shuffle::Resharable},
            generate_permutation::{
                generate_permutation_and_reveal_shuffled,
                malicious_generate_permutation_and_reveal_shuffled,
            },
        },
        RecordId, Substep,
    },
    secret_sharing::{
        replicated::{
            malicious::AdditiveShare as MaliciousReplicated,
            semi_honest::{AdditiveShare as Replicated, XorShare as XorReplicated},
        },
        Arithmetic,
    },
};

use async_trait::async_trait;
use futures::future::{try_join, try_join3, try_join_all};
use generic_array::{ArrayLength, GenericArray};
use std::ops::Add;
use std::{
    iter::{repeat, zip},
    marker::PhantomData,
};
use typenum::Unsigned;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
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

impl Substep for Step {}

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

#[derive(Debug)]
#[cfg_attr(test, derive(Clone, PartialEq, Eq))]
pub struct IPAInputRow<F: Field, MK: Fp2Array, BK: Fp2Array> {
    pub mk_shares: XorReplicated<MK>,
    pub is_trigger_bit: Replicated<F>,
    pub breakdown_key: XorReplicated<BK>,
    pub trigger_value: Replicated<F>,
}

impl<F: Field, MK: Fp2Array, BK: Fp2Array> Serializable for IPAInputRow<F, MK, BK>
where
    XorReplicated<BK>: Serializable,
    XorReplicated<MK>: Serializable,
    Replicated<F>: Serializable,
    <XorReplicated<BK> as Serializable>::Size: Add<<Replicated<F> as Serializable>::Size>,
    <Replicated<F> as Serializable>::Size:
        Add<
            <<XorReplicated<BK> as Serializable>::Size as Add<
                <Replicated<F> as Serializable>::Size,
            >>::Output,
        >,
    <XorReplicated<MK> as Serializable>::Size: Add<
        <<Replicated<F> as Serializable>::Size as Add<
            <<XorReplicated<BK> as Serializable>::Size as Add<
                <Replicated<F> as Serializable>::Size,
            >>::Output,
        >>::Output,
    >,
    <<XorReplicated<MK> as Serializable>::Size as Add<
        <<Replicated<F> as Serializable>::Size as Add<
            <<XorReplicated<BK> as Serializable>::Size as Add<
                <Replicated<F> as Serializable>::Size,
            >>::Output,
        >>::Output,
    >>::Output: ArrayLength<u8>,
{
    type Size = <<XorReplicated<MK> as Serializable>::Size as Add<
        <<Replicated<F> as Serializable>::Size as Add<
            <<XorReplicated<BK> as Serializable>::Size as Add<
                <Replicated<F> as Serializable>::Size,
            >>::Output,
        >>::Output,
    >>::Output;

    fn serialize(self, buf: &mut GenericArray<u8, Self::Size>) {
        let mk_sz = <XorReplicated<MK> as Serializable>::Size::USIZE;
        let bk_sz = <XorReplicated<BK> as Serializable>::Size::USIZE;
        let f_sz = <Replicated<F> as Serializable>::Size::USIZE;

        self.mk_shares
            .serialize(GenericArray::from_mut_slice(&mut buf[..mk_sz]));
        self.is_trigger_bit
            .serialize(GenericArray::from_mut_slice(&mut buf[mk_sz..mk_sz + f_sz]));
        self.breakdown_key.serialize(GenericArray::from_mut_slice(
            &mut buf[mk_sz + f_sz..mk_sz + f_sz + bk_sz],
        ));
        self.trigger_value.serialize(GenericArray::from_mut_slice(
            &mut buf[mk_sz + f_sz + bk_sz..],
        ));
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        let mk_sz = <XorReplicated<MK> as Serializable>::Size::USIZE;
        let bk_sz = <XorReplicated<BK> as Serializable>::Size::USIZE;
        let f_sz = <Replicated<F> as Serializable>::Size::USIZE;

        let mk_shares = XorReplicated::<MK>::deserialize(GenericArray::from_slice(&buf[..mk_sz]));
        let is_trigger_bit =
            Replicated::<F>::deserialize(GenericArray::from_slice(&buf[mk_sz..mk_sz + f_sz]));
        let breakdown_key = XorReplicated::<BK>::deserialize(GenericArray::from_slice(
            &buf[mk_sz + f_sz..mk_sz + f_sz + bk_sz],
        ));
        let trigger_value =
            Replicated::<F>::deserialize(GenericArray::from_slice(&buf[mk_sz + f_sz + bk_sz..]));
        Self {
            mk_shares,
            is_trigger_bit,
            breakdown_key,
            trigger_value,
        }
    }
}

impl<F: Field, MK: Fp2Array, BK: Fp2Array> IPAInputRow<F, MK, BK>
where
    IPAInputRow<F, MK, BK>: Serializable,
{
    /// Splits the given slice into chunks aligned with the size of this struct and returns an
    /// iterator that produces deserialized instances.
    ///
    /// ## Panics
    /// Panics if the slice buffer is not aligned with the size of this struct.
    pub fn from_byte_slice(input: &[u8]) -> impl Iterator<Item = Self> + '_ {
        assert_eq!(
            0,
            input.len() % <IPAInputRow<F, MK, BK> as Serializable>::Size::USIZE,
            "input is not aligned"
        );
        input
            .chunks(<IPAInputRow<F, MK, BK> as Serializable>::Size::USIZE)
            .map(|chunk| IPAInputRow::<F, MK, BK>::deserialize(GenericArray::from_slice(chunk)))
    }
}

pub struct IPAModulusConvertedInputRow<F: Field, T: Arithmetic<F>> {
    mk_shares: Vec<T>,
    is_trigger_bit: T,
    breakdown_key: Vec<T>,
    trigger_value: T,
    _marker: PhantomData<F>,
}

impl<F: Field, T: Arithmetic<F>> IPAModulusConvertedInputRow<F, T> {
    pub fn new(
        mk_shares: Vec<T>,
        is_trigger_bit: T,
        breakdown_key: Vec<T>,
        trigger_value: T,
    ) -> Self {
        Self {
            mk_shares,
            is_trigger_bit,
            breakdown_key,
            trigger_value,
            _marker: PhantomData,
        }
    }
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

        let (mk_shares, breakdown_key, (is_trigger_bit, trigger_value)) = try_join3(
            f_mk_shares,
            f_breakdown_key,
            try_join(f_is_trigger_bit, f_trigger_value),
        )
        .await?;

        Ok(IPAModulusConvertedInputRow::new(
            mk_shares,
            is_trigger_bit,
            breakdown_key,
            trigger_value,
        ))
    }
}

/// # Errors
/// Propagates errors from multiplications
/// # Panics
/// Propagates errors from multiplications
pub async fn ipa<F, MK, BK>(
    ctx: SemiHonestContext<'_, F>,
    input_rows: &[IPAInputRow<F, MK, BK>],
    per_user_credit_cap: u32,
    max_breakdown_key: u128,
    num_multi_bits: u32,
) -> Result<Vec<MCAggregateCreditOutputRow<F, Replicated<F>, BK>>, Error>
where
    F: Field,
    MK: Fp2Array,
    BK: Fp2Array,
    Replicated<F>: Serializable,
{
    let (mk_shares, bk_shares): (Vec<_>, Vec<_>) = input_rows
        .iter()
        .map(|x| (x.mk_shares.clone(), x.breakdown_key.clone()))
        .unzip();

    // TODO (richaj) need to revisit convert_all_bits and make it return iterator on a slice for sort
    // or, a complete slice for breakdown keys. For now, converted_bk_shares has just 1 slice inside
    // the outermost vector
    // Breakdown key modulus conversion
    let mut converted_bk_shares = convert_all_bits(
        &ctx.narrow(&Step::ModulusConversionForBreakdownKeys),
        &convert_all_bits_local(ctx.role(), &bk_shares),
        BK::BITS,
        BK::BITS,
    )
    .await
    .unwrap();
    let converted_bk_shares = converted_bk_shares.pop().unwrap();

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

    let converted_mk_shares = combine_slices(&converted_mk_shares, MK::BITS);

    let combined_match_keys_and_sidecar_data =
        std::iter::zip(converted_mk_shares, converted_bk_shares)
            .into_iter()
            .zip(input_rows)
            .map(|((mk_shares, bk_shares), input_row)| {
                IPAModulusConvertedInputRow::new(
                    mk_shares,
                    input_row.is_trigger_bit.clone(),
                    bk_shares,
                    input_row.trigger_value.clone(),
                )
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
        .map(|(row, hb)| {
            MCAccumulateCreditInputRow::new(
                row.is_trigger_bit,
                hb,
                row.breakdown_key,
                row.trigger_value,
            )
        })
        .collect::<Vec<_>>();

    let accumulated_credits = accumulate_credit(
        ctx.narrow(&Step::AccumulateCredit),
        &attribution_input_rows,
        per_user_credit_cap,
    )
    .await?;

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
/// We return `Replicated<F>` as output since there is compute after this and in `aggregate_credit`, last communication operation was sort
/// # Errors
/// Propagates errors from multiplications
/// # Panics
/// Propagates errors from multiplications
#[allow(dead_code, clippy::too_many_lines)]
pub async fn ipa_malicious<'a, F, MK, BK>(
    sh_ctx: SemiHonestContext<'a, F>,
    input_rows: &[IPAInputRow<F, MK, BK>],
    per_user_credit_cap: u32,
    max_breakdown_key: u128,
    num_multi_bits: u32,
) -> Result<Vec<MCAggregateCreditOutputRow<F, Replicated<F>, BK>>, Error>
where
    F: Field,
    MK: Fp2Array,
    BK: Fp2Array,
    MaliciousReplicated<F>: Serializable,
    Replicated<F>: Serializable,
{
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

    let converted_mk_shares = combine_slices(&converted_mk_shares, MK::BITS);

    // Breakdown key modulus conversion
    let mut converted_bk_shares = convert_all_bits(
        &m_ctx.narrow(&Step::ModulusConversionForBreakdownKeys),
        &m_ctx
            .narrow(&Step::ModulusConversionForBreakdownKeys)
            .upgrade(convert_all_bits_local(m_ctx.role(), &bk_shares))
            .await?,
        BK::BITS,
        BK::BITS,
    )
    .await
    .unwrap();

    let converted_bk_shares = converted_bk_shares.pop().unwrap();

    let intermediate = converted_mk_shares
        .into_iter()
        .zip(input_rows)
        .map(|(mk_shares, input_row)| {
            IPAModulusConvertedInputRowWrapper::new(
                mk_shares,
                input_row.is_trigger_bit.clone(),
                input_row.trigger_value.clone(),
            )
        })
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
                _marker: PhantomData,
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
        .map(|(row, hb)| {
            MCAccumulateCreditInputRow::new(
                row.is_trigger_bit,
                hb,
                row.breakdown_key,
                row.trigger_value,
            )
        })
        .collect::<Vec<_>>();

    let accumulated_credits = accumulate_credit(
        m_ctx.narrow(&Step::AccumulateCredit),
        &attribution_input_rows,
        per_user_credit_cap,
    )
    .await?;

    let user_capped_credits = credit_capping(
        m_ctx.narrow(&Step::PerformUserCapping),
        &accumulated_credits,
        per_user_credit_cap,
    )
    .await?;

    //Validate before calling sort with downgraded context
    let (malicious_validator, output) = malicious_aggregate_credit::<F, BK>(
        malicious_validator,
        sh_ctx,
        &user_capped_credits,
        max_breakdown_key,
        num_multi_bits,
    )
    .await?;
    malicious_validator.validate(output).await
}

#[cfg(all(test, not(feature = "shuttle")))]
pub mod tests {
    use super::{ipa, ipa_malicious, IPAInputRow};
    use crate::bits::{Fp2Array, Serializable};
    use crate::ff::{Field, Fp31, Fp32BitPrime};
    use crate::ipa_test_input;
    use crate::protocol::{BreakdownKey, MatchKey};
    use crate::secret_sharing::IntoShares;
    use crate::telemetry::metrics::RECORDS_SENT;
    use crate::test_fixture::{
        input::GenericReportTestInput, Reconstruct, Runner, TestWorld, TestWorldConfig,
    };
    use generic_array::GenericArray;
    use proptest::{
        proptest,
        test_runner::{RngAlgorithm, TestRng},
    };
    use rand::rngs::StdRng;
    use rand::{thread_rng, Rng};
    use rand_core::SeedableRng;
    use typenum::Unsigned;

    #[tokio::test]
    #[allow(clippy::missing_panics_doc)]
    pub async fn semi_honest() {
        const COUNT: usize = 5;
        const PER_USER_CAP: u32 = 3;
        const EXPECTED: &[[u128; 2]] = &[[0, 0], [1, 2], [2, 3]];
        const MAX_BREAKDOWN_KEY: u128 = 3;
        const NUM_MULTI_BITS: u32 = 3;

        let world = TestWorld::new().await;

        let records: Vec<GenericReportTestInput<_, MatchKey, BreakdownKey>> = ipa_test_input!(
            [
                { match_key: 12345, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { match_key: 12345, is_trigger_report: 0, breakdown_key: 2, trigger_value: 0 },
                { match_key: 68362, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 5 },
                { match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 2 },
            ];
            (Fp31, MatchKey, BreakdownKey)
        );

        let result: Vec<GenericReportTestInput<_, MatchKey, BreakdownKey>> = world
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

        let result: Vec<GenericReportTestInput<_, MatchKey, BreakdownKey>> = world
            .semi_honest(records, |ctx, input_rows| async move {
                ipa_malicious::<_, MatchKey, BreakdownKey>(
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
    async fn cap_of_one() {
        const PER_USER_CAP: u32 = 1;
        const EXPECTED: &[[u128; 2]] = &[[0, 0], [1, 1], [2, 0], [3, 0], [4, 0], [5, 1], [6, 1]];
        const MAX_BREAKDOWN_KEY: u128 = 7;
        const NUM_MULTI_BITS: u32 = 3;

        let world = TestWorld::new().await;

        let records: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> = ipa_test_input!(
            [
                { match_key: 12345, is_trigger_report: 0, breakdown_key: 0, trigger_value: 0 }, // Irrelevant
                { match_key: 12345, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 }, // A
                { match_key: 68362, is_trigger_report: 0, breakdown_key: 2, trigger_value: 0 }, // B
                { match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 0 }, // This will be attributed to A
                { match_key: 77777, is_trigger_report: 1, breakdown_key: 1, trigger_value: 0 }, // Irrelevant
                { match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 0 }, // This will be attributed to B, but will be capped
                { match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 0 }, // Irrelevant
                { match_key: 68362, is_trigger_report: 0, breakdown_key: 3, trigger_value: 0 }, // C
                { match_key: 77777, is_trigger_report: 0, breakdown_key: 4, trigger_value: 0 }, // Irrelevant
                { match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 0 }, // This will be attributed to C, but will be capped
                { match_key: 81818, is_trigger_report: 0, breakdown_key: 6, trigger_value: 0 }, // E
                { match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 0 }, // Irrelevant
                { match_key: 81818, is_trigger_report: 1, breakdown_key: 0, trigger_value: 0 }, // This will be attributed to E
                { match_key: 68362, is_trigger_report: 0, breakdown_key: 5, trigger_value: 0 }, // D
                { match_key: 99999, is_trigger_report: 0, breakdown_key: 6, trigger_value: 0 }, // Irrelevant
                { match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 0 }, // This will be attributed to D

            ];
            (Fp31, MatchKey, BreakdownKey)
        );

        let result: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> = world
            .semi_honest(records.clone(), |ctx, input_rows| async move {
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

        let result: Vec<GenericReportTestInput<_, MatchKey, BreakdownKey>> = world
            .semi_honest(records, |ctx, input_rows| async move {
                ipa_malicious::<_, MatchKey, BreakdownKey>(
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

    #[derive(Debug, Clone)]
    struct TestRawDataRecord {
        user_id: usize,
        timestamp: usize,
        is_trigger_report: bool,
        breakdown_key: usize,
        trigger_value: u32,
    }

    fn generate_random_user_records_in_reverse_chronological_order(
        rng: &mut impl Rng,
        max_records_per_user: usize,
        max_breakdown_key: usize,
        max_trigger_value: u32,
    ) -> Vec<TestRawDataRecord> {
        const MAX_USER_ID: usize = 1_000_000_000_000;
        const SECONDS_IN_EPOCH: usize = 604_800;

        let random_user_id = rng.gen_range(0..MAX_USER_ID);
        let num_records_for_user = rng.gen_range(1..max_records_per_user);
        let mut records_for_user = Vec::with_capacity(num_records_for_user);
        for _ in 0..num_records_for_user {
            let random_timestamp = rng.gen_range(0..SECONDS_IN_EPOCH);
            let is_trigger_report = rng.gen::<bool>();
            let random_breakdown_key = if is_trigger_report {
                0
            } else {
                rng.gen_range(0..max_breakdown_key)
            };
            let trigger_value = if is_trigger_report {
                rng.gen_range(1..max_trigger_value)
            } else {
                0
            };
            records_for_user.push(TestRawDataRecord {
                user_id: random_user_id,
                timestamp: random_timestamp,
                is_trigger_report,
                breakdown_key: random_breakdown_key,
                trigger_value,
            });
        }

        // sort in reverse time order
        records_for_user.sort_unstable_by(|a, b| b.timestamp.cmp(&a.timestamp));

        records_for_user
    }

    /// Assumes records all belong to the same user, and are in reverse chronological order
    /// Will give incorrect results if this is not true
    fn update_expected_output_for_user(
        records_for_user: &[TestRawDataRecord],
        expected_results: &mut [u32],
        per_user_cap: u32,
    ) {
        let mut pending_trigger_value = 0;
        let mut total_contribution = 0;
        for record in records_for_user {
            if total_contribution >= per_user_cap {
                break;
            }

            if record.is_trigger_report {
                pending_trigger_value += record.trigger_value;
            } else if pending_trigger_value > 0 {
                let delta_to_per_user_cap = per_user_cap - total_contribution;
                let capped_contribution =
                    std::cmp::min(delta_to_per_user_cap, pending_trigger_value);
                expected_results[record.breakdown_key] += capped_contribution;
                total_contribution += capped_contribution;
                pending_trigger_value = 0;
            }
        }
    }

    async fn test_ipa_semi_honest(
        world: TestWorld,
        records: &[TestRawDataRecord],
        expected_results: &[u32],
        per_user_cap: u32,
        max_breakdown_key: usize,
    ) {
        const NUM_MULTI_BITS: u32 = 3;

        let records = records
            .iter()
            .map(|x| {
                ipa_test_input!(
                    {
                        match_key: x.user_id,
                        is_trigger_report: x.is_trigger_report,
                        breakdown_key: x.breakdown_key,
                        trigger_value: x.trigger_value,
                    };
                    (Fp32BitPrime, MatchKey, BreakdownKey)
                )
            })
            .collect::<Vec<_>>();

        let result: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = world
            .semi_honest(records, |ctx, input_rows| async move {
                ipa::<Fp32BitPrime, MatchKey, BreakdownKey>(
                    ctx,
                    &input_rows,
                    per_user_cap,
                    max_breakdown_key as u128,
                    NUM_MULTI_BITS,
                )
                .await
                .unwrap()
            })
            .await
            .reconstruct();

        assert_eq!(max_breakdown_key, result.len());
        println!(
            "actual results: {:#?}",
            result
                .iter()
                .map(|x| x.trigger_value.as_u128())
                .collect::<Vec<_>>(),
        );
        for (i, expected) in expected_results.iter().enumerate() {
            assert_eq!(
                [i as u128, u128::from(*expected)],
                [
                    result[i].breakdown_key.as_u128(),
                    result[i].trigger_value.as_u128()
                ]
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::missing_panics_doc)]
    pub async fn random_ipa_check() {
        const MAX_BREAKDOWN_KEY: usize = 16;
        const MAX_TRIGGER_VALUE: u32 = 5;
        const NUM_USERS: usize = 10;
        const MAX_RECORDS_PER_USER: usize = 8;
        const NUM_MULTI_BITS: u32 = 3;

        let random_seed = thread_rng().gen();
        println!("Using random seed: {random_seed}");
        let mut rng = StdRng::seed_from_u64(random_seed);

        let mut random_user_records = Vec::with_capacity(NUM_USERS);
        for _ in 0..NUM_USERS {
            let records_for_user = generate_random_user_records_in_reverse_chronological_order(
                &mut rng,
                MAX_RECORDS_PER_USER,
                MAX_BREAKDOWN_KEY,
                MAX_TRIGGER_VALUE,
            );
            random_user_records.push(records_for_user);
        }
        let mut raw_data = random_user_records.concat();

        // Sort the records in chronological order
        // This is part of the IPA spec. Callers should do this before sending a batch of records in for processing.
        raw_data.sort_unstable_by(|a, b| a.timestamp.cmp(&b.timestamp));

        for per_user_cap in [1, 3] {
            let mut expected_results = vec![0_u32; MAX_BREAKDOWN_KEY];

            for records_for_user in &random_user_records {
                update_expected_output_for_user(
                    records_for_user,
                    &mut expected_results,
                    per_user_cap,
                );
            }

            let world = TestWorld::new().await;

            test_ipa_semi_honest(
                world,
                &raw_data,
                &expected_results,
                per_user_cap,
                MAX_BREAKDOWN_KEY,
            )
            .await;
        }
    }

    fn serde_internal(
        match_key: u64,
        trigger_bit: u128,
        breakdown_key: u128,
        trigger_value: u128,
        seed: u128,
    ) {
        // xorshift requires 16 byte seed and that's why it is picked here
        let mut rng = TestRng::from_seed(RngAlgorithm::XorShift, &seed.to_le_bytes());
        let reports: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> = ipa_test_input!(
            [
                { match_key: match_key, is_trigger_report: trigger_bit, breakdown_key: breakdown_key, trigger_value: trigger_value },
            ];
            (Fp31, MatchKey, BreakdownKey)
        );
        let [a, b, ..]: [IPAInputRow<Fp31, MatchKey, BreakdownKey>; 3] =
            reports[0].share_with(&mut rng);

        let mut buf =
            vec![0u8; 2 * <IPAInputRow<Fp31, MatchKey, BreakdownKey> as Serializable>::Size::USIZE];
        a.clone().serialize(GenericArray::from_mut_slice(
            &mut buf[..<IPAInputRow<Fp31, MatchKey, BreakdownKey> as Serializable>::Size::USIZE],
        ));
        b.clone().serialize(GenericArray::from_mut_slice(
            &mut buf[<IPAInputRow<Fp31, MatchKey, BreakdownKey> as Serializable>::Size::USIZE..],
        ));

        assert_eq!(
            vec![a, b],
            IPAInputRow::<Fp31, MatchKey, BreakdownKey>::from_byte_slice(&buf).collect::<Vec<_>>()
        );
    }

    proptest! {
        #[test]
        fn serde(match_key in 0..u64::MAX, trigger_bit in 0..u128::MAX, breakdown_key in 0..u128::MAX, trigger_value in 0..u128::MAX, seed in 0..u128::MAX) {
            serde_internal(match_key, trigger_bit, breakdown_key, trigger_value, seed);
        }
    }

    /// Ensures that our communication numbers don't go above the baseline.
    /// Prints a warning if they are currently below, so someone needs to adjust the baseline
    /// inside this test.
    ///
    /// It is possible to increase the number too if there is a good reason for it. This is a
    /// "catch all" type of test to make sure we don't miss an accidental regression.
    #[tokio::test]
    pub async fn communication_baseline() {
        const MAX_BREAKDOWN_KEY: u128 = 3;
        const NUM_MULTI_BITS: u32 = 3;

        /// empirical value as of Feb 4, 2023.
        const RECORDS_SENT_SEMI_HONEST_BASELINE_CAP_3: u64 = 10740;

        /// empirical value as of Feb 14, 2023.
        const RECORDS_SENT_MALICIOUS_BASELINE_CAP_3: u64 = 26410;

        /// empirical value as of Feb 20, 2023.
        const RECORDS_SENT_SEMI_HONEST_BASELINE_CAP_1: u64 = 7557;

        /// empirical value as of Feb 20, 2023.
        const RECORDS_SENT_MALICIOUS_BASELINE_CAP_1: u64 = 18849;

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

        for per_user_cap in [1, 3] {
            let world = TestWorld::new_with(*TestWorldConfig::default().enable_metrics()).await;

            let _: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = world
                .semi_honest(records.clone(), |ctx, input_rows| async move {
                    ipa::<Fp32BitPrime, MatchKey, BreakdownKey>(
                        ctx,
                        &input_rows,
                        per_user_cap,
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
            let semi_honest_baseline = if per_user_cap == 1 {
                RECORDS_SENT_SEMI_HONEST_BASELINE_CAP_1
            } else {
                RECORDS_SENT_SEMI_HONEST_BASELINE_CAP_3
            };
            assert!(records_sent <= semi_honest_baseline,
                "Baseline for semi-honest IPA (cap = {per_user_cap}) has DEGRADED! Expected {semi_honest_baseline}, got {records_sent}.");

            if records_sent < semi_honest_baseline {
                tracing::warn!("Baseline for semi-honest IPA (cap = {per_user_cap}) has improved! Expected {semi_honest_baseline}, got {records_sent}.\
                                Strongly consider adjusting the baseline, so the gains won't be accidentally offset by a regression.");
            }

            let world = TestWorld::new_with(*TestWorldConfig::default().enable_metrics()).await;

            let _ = world
                .semi_honest(records.clone(), |ctx, input_rows| async move {
                    ipa_malicious::<Fp32BitPrime, MatchKey, BreakdownKey>(
                        ctx,
                        &input_rows,
                        per_user_cap,
                        MAX_BREAKDOWN_KEY,
                        NUM_MULTI_BITS,
                    )
                    .await
                    .unwrap()
                })
                .await;

            let snapshot = world.metrics_snapshot();
            let records_sent = snapshot.get_counter(RECORDS_SENT);
            let malicious_baseline = if per_user_cap == 1 {
                RECORDS_SENT_MALICIOUS_BASELINE_CAP_1
            } else {
                RECORDS_SENT_MALICIOUS_BASELINE_CAP_3
            };

            if records_sent < malicious_baseline {
                tracing::warn!("Baseline for malicious IPA (cap = {per_user_cap}) has improved! Expected {malicious_baseline}, got {records_sent}.\
                Strongly consider adjusting the baseline, so the gains won't be accidentally offset by a regression.");
            }

            assert!(records_sent <= malicious_baseline,
                "Baseline for malicious IPA (cap = {per_user_cap}) has DEGRADED! Expected {malicious_baseline}, got {records_sent}.");
        }
    }
}
