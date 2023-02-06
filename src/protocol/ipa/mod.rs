use crate::{
    bits::{BitArray, Serializable},
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
use futures::future::{try_join3, try_join_all};
use generic_array::{ArrayLength, GenericArray};
use std::ops::Add;
use std::{
    iter::{repeat, zip},
    marker::PhantomData,
};
use typenum::Unsigned;

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
pub struct IPAInputRow<F: Field, MK: BitArray, BK: BitArray> {
    pub mk_shares: XorReplicated<MK>,
    pub is_trigger_bit: Replicated<F>,
    pub breakdown_key: XorReplicated<BK>,
    pub trigger_value: Replicated<F>,
}

impl<F: Field, MK: BitArray, BK: BitArray> Serializable for IPAInputRow<F, MK, BK>
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
        self.mk_shares.serialize(GenericArray::from_mut_slice(
            &mut buf[..<XorReplicated<MK> as Serializable>::Size::USIZE],
        ));
        self.is_trigger_bit.serialize(GenericArray::from_mut_slice(
            &mut buf[<XorReplicated<MK> as Serializable>::Size::USIZE
                ..<XorReplicated<MK> as Serializable>::Size::USIZE
                    + <Replicated<F> as Serializable>::Size::USIZE],
        ));
        self.breakdown_key.serialize(GenericArray::from_mut_slice(
            &mut buf[<XorReplicated<MK> as Serializable>::Size::USIZE
                + <Replicated<F> as Serializable>::Size::USIZE
                ..<XorReplicated<MK> as Serializable>::Size::USIZE
                    + <Replicated<F> as Serializable>::Size::USIZE
                    + <XorReplicated<BK> as Serializable>::Size::USIZE],
        ));
        self.trigger_value.serialize(GenericArray::from_mut_slice(
            &mut buf[<XorReplicated<MK> as Serializable>::Size::USIZE
                + <Replicated<F> as Serializable>::Size::USIZE
                + <XorReplicated<BK> as Serializable>::Size::USIZE..],
        ));
    }

    fn deserialize(buf: GenericArray<u8, Self::Size>) -> Self {
        let mk_shares = XorReplicated::<MK>::deserialize(GenericArray::clone_from_slice(
            &buf[..<XorReplicated<MK> as Serializable>::Size::USIZE],
        ));
        let is_trigger_bit = Replicated::<F>::deserialize(GenericArray::clone_from_slice(
            &buf[<XorReplicated<MK> as Serializable>::Size::USIZE
                ..<XorReplicated<MK> as Serializable>::Size::USIZE
                    + <Replicated<F> as Serializable>::Size::USIZE],
        ));
        let breakdown_key = XorReplicated::<BK>::deserialize(GenericArray::clone_from_slice(
            &buf[<XorReplicated<MK> as Serializable>::Size::USIZE
                + <Replicated<F> as Serializable>::Size::USIZE
                ..<XorReplicated<MK> as Serializable>::Size::USIZE
                    + <Replicated<F> as Serializable>::Size::USIZE
                    + <XorReplicated<BK> as Serializable>::Size::USIZE],
        ));
        let trigger_value = Replicated::<F>::deserialize(GenericArray::clone_from_slice(
            &buf[<XorReplicated<MK> as Serializable>::Size::USIZE
                + <Replicated<F> as Serializable>::Size::USIZE
                + <XorReplicated<BK> as Serializable>::Size::USIZE..],
        ));
        Self {
            mk_shares,
            is_trigger_bit,
            breakdown_key,
            trigger_value,
        }
    }
}

impl<F: Field, MK: BitArray, BK: BitArray> IPAInputRow<F, MK, BK>
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
            .map(|chunk| {
                IPAInputRow::<F, MK, BK>::deserialize(GenericArray::clone_from_slice(chunk))
            })
    }
}

pub struct IPAModulusConvertedInputRow<F: Field, T: Arithmetic<F>> {
    pub mk_shares: Vec<T>,
    pub is_trigger_bit: T,
    pub breakdown_key: Vec<T>,
    pub trigger_value: T,
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
            _marker: PhantomData::default(),
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
pub async fn ipa<F: Field, MK: BitArray, BK: BitArray>(
    ctx: SemiHonestContext<'_, F>,
    input_rows: &[IPAInputRow<F, MK, BK>],
    per_user_credit_cap: u32,
    max_breakdown_key: u128,
    num_multi_bits: u32,
) -> Result<Vec<MCAggregateCreditOutputRow<F, Replicated<F>, BK>>, Error>
where
    Replicated<F>: Serializable,
{
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
    let converted_bk_shares = combine_slices(&converted_bk_shares, BK::BITS);

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
        &converted_mk_shares,
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
) -> Result<Vec<MCAggregateCreditOutputRow<F, MaliciousReplicated<F>, BK>>, Error>
where
    F: Field,
    MK: BitArray,
    BK: BitArray,
    MaliciousReplicated<F>: Serializable,
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
        &converted_mk_shares,
    )
    .await
    .unwrap();

    let malicious_validator = MaliciousValidator::new(sh_ctx.narrow(&Step::AfterConvertAllBits));
    let m_ctx = malicious_validator.context();

    let converted_mk_shares = combine_slices(&converted_mk_shares, MK::BITS);

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

    let converted_bk_shares = combine_slices(&converted_bk_shares, BK::BITS);

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
    use crate::{
        bits::{BitArray, Serializable},
        ff::{Field, Fp31, Fp32BitPrime},
        ipa_test_input,
        protocol::{
            ipa::{ipa, ipa_wip_malicious, IPAInputRow},
            BreakdownKey, MatchKey,
        },
        rand::thread_rng,
        secret_sharing::IntoShares,
        telemetry::metrics::RECORDS_SENT,
        test_fixture::{
            input::GenericReportTestInput, Reconstruct, Runner, TestWorld, TestWorldConfig,
        },
    };
    use generic_array::GenericArray;
    use proptest::{
        proptest,
        test_runner::{RngAlgorithm, TestRng},
    };
    use rand::Rng;
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
    async fn malicious_wip() {
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
