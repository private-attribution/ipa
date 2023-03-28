use crate::{
    error::Error,
    ff::{Field, GaloisField, Gf2, PrimeField, Serializable},
    helpers::Role,
    protocol::{
        attribution::{input::MCAggregateCreditOutputRow, malicious, semi_honest},
        basics::Reshare,
        context::{
            malicious::IPAModulusConvertedInputRowWrapper, Context, MaliciousContext,
            SemiHonestContext,
        },
        malicious::MaliciousValidator,
        modulus_conversion::{convert_all_bits, convert_all_bits_local},
        sort::{
            apply_sort::apply_sort_permutation,
            generate_permutation::{
                generate_permutation_and_reveal_shuffled,
                malicious_generate_permutation_and_reveal_shuffled,
            },
        },
        BasicProtocols, RecordId, Substep,
    },
    secret_sharing::{
        replicated::{
            malicious::{AdditiveShare as MaliciousReplicated, ExtendableField},
            semi_honest::AdditiveShare as Replicated,
            ReplicatedSecretSharing,
        },
        Linear as LinearSecretSharing,
    },
};

use async_trait::async_trait;
use futures::future::{try_join, try_join3};
use generic_array::{ArrayLength, GenericArray};
use std::{marker::PhantomData, ops::Add};
use typenum::Unsigned;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
    ModulusConversionForMatchKeys,
    ModulusConversionForBreakdownKeys,
    GenSortPermutationFromMatchKeys,
    ApplySortPermutation,
    ApplySortPermutationToMatchKeys,
    ApplySortPermutationToBreakdownKeys,
    AfterConvertAllBits,
    BinaryValidator,
    BreakdownKeyValdator,
}

impl Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::ModulusConversionForMatchKeys => "mod_conv_match_key",
            Self::ModulusConversionForBreakdownKeys => "mod_conv_breakdown_key",
            Self::GenSortPermutationFromMatchKeys => "gen_sort_permutation_from_match_keys",
            Self::ApplySortPermutation => "apply_sort_permutation",
            Self::ApplySortPermutationToMatchKeys => "apply_sort_permutation_to_match_keys",
            Self::ApplySortPermutationToBreakdownKeys => "apply_sort_permutation_to_breakdown_keys",
            Self::AfterConvertAllBits => "after_convert_all_bits",
            Self::BinaryValidator => "binary_validator",
            Self::BreakdownKeyValdator => "breakdown_key_validator",
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
pub struct IPAInputRow<F: Field, MK: GaloisField, BK: GaloisField> {
    pub mk_shares: Replicated<MK>,
    pub is_trigger_bit: Replicated<F>,
    pub breakdown_key: Replicated<BK>,
    pub trigger_value: Replicated<F>,
}

impl<F: Field, MK: GaloisField, BK: GaloisField> Serializable for IPAInputRow<F, MK, BK>
where
    Replicated<BK>: Serializable,
    Replicated<MK>: Serializable,
    Replicated<F>: Serializable,
    <Replicated<BK> as Serializable>::Size: Add<<Replicated<F> as Serializable>::Size>,
    <Replicated<F> as Serializable>::Size:
        Add<
            <<Replicated<BK> as Serializable>::Size as Add<
                <Replicated<F> as Serializable>::Size,
            >>::Output,
        >,
    <Replicated<MK> as Serializable>::Size: Add<
        <<Replicated<F> as Serializable>::Size as Add<
            <<Replicated<BK> as Serializable>::Size as Add<
                <Replicated<F> as Serializable>::Size,
            >>::Output,
        >>::Output,
    >,
    <<Replicated<MK> as Serializable>::Size as Add<
        <<Replicated<F> as Serializable>::Size as Add<
            <<Replicated<BK> as Serializable>::Size as Add<
                <Replicated<F> as Serializable>::Size,
            >>::Output,
        >>::Output,
    >>::Output: ArrayLength<u8>,
{
    type Size = <<Replicated<MK> as Serializable>::Size as Add<
        <<Replicated<F> as Serializable>::Size as Add<
            <<Replicated<BK> as Serializable>::Size as Add<
                <Replicated<F> as Serializable>::Size,
            >>::Output,
        >>::Output,
    >>::Output;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        let mk_sz = <Replicated<MK> as Serializable>::Size::USIZE;
        let bk_sz = <Replicated<BK> as Serializable>::Size::USIZE;
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
        let mk_sz = <Replicated<MK> as Serializable>::Size::USIZE;
        let bk_sz = <Replicated<BK> as Serializable>::Size::USIZE;
        let f_sz = <Replicated<F> as Serializable>::Size::USIZE;

        let mk_shares = Replicated::<MK>::deserialize(GenericArray::from_slice(&buf[..mk_sz]));
        let is_trigger_bit =
            Replicated::<F>::deserialize(GenericArray::from_slice(&buf[mk_sz..mk_sz + f_sz]));
        let breakdown_key = Replicated::<BK>::deserialize(GenericArray::from_slice(
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

impl<F: Field, MK: GaloisField, BK: GaloisField> IPAInputRow<F, MK, BK>
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

pub struct IPAModulusConvertedInputRow<F: Field, T: LinearSecretSharing<F>> {
    pub is_trigger_bit: T,
    pub trigger_value: T,
    _marker: PhantomData<F>,
}

impl<F: Field, T: LinearSecretSharing<F>> IPAModulusConvertedInputRow<F, T> {
    pub fn new(is_trigger_bit: T, trigger_value: T) -> Self {
        Self {
            is_trigger_bit,
            trigger_value,
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<F, T, C> Reshare<C, RecordId> for IPAModulusConvertedInputRow<F, T>
where
    F: Field,
    T: LinearSecretSharing<F> + Reshare<C, RecordId>,
    C: Context,
{
    async fn reshare<'fut>(
        &self,
        ctx: C,
        record_id: RecordId,
        to_helper: Role,
    ) -> Result<Self, Error>
    where
        C: 'fut,
    {
        let f_is_trigger_bit = self.is_trigger_bit.reshare(
            ctx.narrow(&IPAInputRowResharableStep::TriggerBit),
            record_id,
            to_helper,
        );
        let f_trigger_value = self.trigger_value.reshare(
            ctx.narrow(&IPAInputRowResharableStep::TriggerValue),
            record_id,
            to_helper,
        );

        let (is_trigger_bit, trigger_value) = try_join(f_is_trigger_bit, f_trigger_value).await?;

        Ok(IPAModulusConvertedInputRow::new(
            is_trigger_bit,
            trigger_value,
        ))
    }
}

/// # Errors
/// Propagates errors from multiplications
/// # Panics
/// Propagates errors from multiplications
pub async fn ipa<F, MK, BK>(
    ctx: SemiHonestContext<'_>,
    input_rows: &[IPAInputRow<F, MK, BK>],
    per_user_credit_cap: u32,
    max_breakdown_key: u32,
    attribution_window_seconds: u32,
    num_multi_bits: u32,
) -> Result<Vec<MCAggregateCreditOutputRow<F, Replicated<F>, BK>>, Error>
where
    F: PrimeField,
    MK: GaloisField,
    BK: GaloisField,
    Replicated<F>: Serializable,
{
    let mk_shares: Vec<_> = input_rows
        .iter()
        .map(|x| x.mk_shares.clone())
        .collect::<Vec<_>>();

    // Match key modulus conversion, and then sort
    let converted_mk_shares = convert_all_bits(
        &ctx.narrow(&Step::ModulusConversionForMatchKeys),
        &convert_all_bits_local::<F, MK>(ctx.role(), mk_shares.into_iter()),
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

    let gf2_match_key_bits = get_gf2_match_key_bits(input_rows);

    let gf2_breakdown_key_bits = get_gf2_breakdown_key_bits(input_rows, max_breakdown_key);

    let inputs_sans_match_keys = input_rows
        .iter()
        .map(|input_row| {
            IPAModulusConvertedInputRow::new(
                input_row.is_trigger_bit.clone(),
                input_row.trigger_value.clone(),
            )
        })
        .collect::<Vec<_>>();

    let sorted_rows = apply_sort_permutation(
        ctx.narrow(&Step::ApplySortPermutation),
        inputs_sans_match_keys,
        &sort_permutation,
    )
    .await
    .unwrap();

    let sorted_match_keys = apply_sort_permutation(
        ctx.narrow(&Step::ApplySortPermutationToMatchKeys),
        gf2_match_key_bits,
        &sort_permutation,
    )
    .await
    .unwrap();

    let sorted_breakdown_keys = apply_sort_permutation(
        ctx.narrow(&Step::ApplySortPermutationToBreakdownKeys),
        gf2_breakdown_key_bits,
        &sort_permutation,
    )
    .await
    .unwrap();

    semi_honest::secure_attribution(
        ctx,
        sorted_match_keys,
        sorted_breakdown_keys,
        sorted_rows,
        per_user_credit_cap,
        max_breakdown_key,
        attribution_window_seconds,
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
    sh_ctx: SemiHonestContext<'a>,
    input_rows: &[IPAInputRow<F, MK, BK>],
    per_user_credit_cap: u32,
    max_breakdown_key: u32,
    attribution_window_seconds: u32,
    num_multi_bits: u32,
) -> Result<Vec<MCAggregateCreditOutputRow<F, Replicated<F>, BK>>, Error>
where
    F: PrimeField + ExtendableField,
    MK: GaloisField,
    BK: GaloisField,
    MaliciousReplicated<F>: Serializable + BasicProtocols<MaliciousContext<'a, F>, F>,
    Replicated<F>: Serializable + BasicProtocols<SemiHonestContext<'a>, F>,
{
    let malicious_validator = MaliciousValidator::<F>::new(sh_ctx.clone());
    let m_ctx = malicious_validator.context();

    let mk_shares: Vec<_> = input_rows
        .iter()
        .map(|x| x.mk_shares.clone())
        .collect::<Vec<_>>();

    // Match key modulus conversion, and then sort
    let converted_mk_shares = convert_all_bits(
        &m_ctx.narrow(&Step::ModulusConversionForMatchKeys),
        &m_ctx
            .upgrade(convert_all_bits_local(m_ctx.role(), mk_shares.into_iter()))
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

    let malicious_validator =
        MaliciousValidator::<F>::new(sh_ctx.narrow(&Step::AfterConvertAllBits));
    let m_ctx = malicious_validator.context();

    let gf2_match_key_bits = get_gf2_match_key_bits(input_rows);

    let match_key_malicious_validator =
        MaliciousValidator::<Gf2>::new(sh_ctx.narrow(&Step::BinaryValidator));
    let match_key_m_ctx = match_key_malicious_validator.context();

    let breakdown_key_validator =
        MaliciousValidator::<Gf2>::new(sh_ctx.narrow(&Step::BreakdownKeyValdator));
    let breakdown_key_m_ctx = breakdown_key_validator.context();

    let upgraded_gf2_match_key_bits = match_key_m_ctx.upgrade(gf2_match_key_bits).await?;

    // Breakdown key modulus conversion
    // MOVE SOMEWHERE ELSE
    // let mut converted_bk_shares = convert_all_bits(
    //     &m_ctx.narrow(&Step::ModulusConversionForBreakdownKeys),
    //     &m_ctx
    //         .narrow(&Step::ModulusConversionForBreakdownKeys)
    //         .upgrade(convert_all_bits_local(m_ctx.role(), bk_shares.into_iter()))
    //         .await?,
    //     BK::BITS,
    //     BK::BITS,
    // )
    // .await
    // .unwrap();

    // let converted_bk_shares = converted_bk_shares.pop().unwrap();

    let gf2_breakdown_key_bits = get_gf2_breakdown_key_bits(input_rows, max_breakdown_key);

    let upgraded_gf2_breakdown_key_bits =
        breakdown_key_m_ctx.upgrade(gf2_breakdown_key_bits).await?;

    let intermediate = input_rows
        .iter()
        .map(|input_row| {
            IPAModulusConvertedInputRowWrapper::new(
                input_row.is_trigger_bit.clone(),
                input_row.trigger_value.clone(),
            )
        })
        .collect::<Vec<_>>();

    let intermediate = m_ctx.upgrade(intermediate).await?;

    let inputs_sans_match_keys = intermediate
        .into_iter()
        .map(
            |one_row| IPAModulusConvertedInputRow::<F, MaliciousReplicated<F>> {
                is_trigger_bit: one_row.is_trigger_bit,
                trigger_value: one_row.trigger_value,
                _marker: PhantomData,
            },
        )
        .collect::<Vec<_>>();

    let sorted_rows = apply_sort_permutation(
        m_ctx.narrow(&Step::ApplySortPermutation),
        inputs_sans_match_keys,
        &sort_permutation,
    )
    .await
    .unwrap();

    let sorted_match_keys = apply_sort_permutation(
        match_key_m_ctx.narrow(&Step::ApplySortPermutation),
        upgraded_gf2_match_key_bits,
        &sort_permutation,
    )
    .await
    .unwrap();

    let sorted_breakdown_keys = apply_sort_permutation(
        breakdown_key_m_ctx.narrow(&Step::ApplySortPermutationToBreakdownKeys),
        upgraded_gf2_breakdown_key_bits,
        &sort_permutation,
    )
    .await
    .unwrap();

    malicious::secure_attribution(
        sh_ctx,
        malicious_validator,
        match_key_malicious_validator,
        breakdown_key_validator,
        sorted_breakdown_keys,
        sorted_match_keys,
        sorted_rows,
        per_user_credit_cap,
        max_breakdown_key,
        attribution_window_seconds,
        num_multi_bits,
    )
    .await
}

fn get_gf2_match_key_bits<F, MK, BK>(
    input_rows: &[IPAInputRow<F, MK, BK>],
) -> Vec<Vec<Replicated<Gf2>>>
where
    F: PrimeField,
    MK: GaloisField,
    BK: GaloisField,
{
    input_rows
        .iter()
        .map(|row| {
            (0..MK::BITS)
                .map(|i| {
                    Replicated::new(
                        Gf2::truncate_from(row.mk_shares.left()[i]),
                        Gf2::truncate_from(row.mk_shares.right()[i]),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
}

fn get_gf2_breakdown_key_bits<F, MK, BK>(
    input_rows: &[IPAInputRow<F, MK, BK>],
    max_breakdown_key: u32,
) -> Vec<Vec<Replicated<Gf2>>>
where
    F: PrimeField,
    MK: GaloisField,
    BK: GaloisField,
{
    let breakdown_key_bits_required = u32::BITS - (max_breakdown_key - 1).leading_zeros();

    input_rows
        .iter()
        .map(|row| {
            (0..breakdown_key_bits_required)
                .map(|i| {
                    Replicated::new(
                        Gf2::truncate_from(row.breakdown_key.left()[i]),
                        Gf2::truncate_from(row.breakdown_key.right()[i]),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
}

#[cfg(all(test, not(feature = "shuttle")))]
pub mod tests {
    use super::{ipa, ipa_malicious, IPAInputRow};
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime, GaloisField, Serializable},
        helpers::GatewayConfig,
        ipa_test_input,
        protocol::{BreakdownKey, MatchKey},
        secret_sharing::IntoShares,
        telemetry::{
            metrics::{BYTES_SENT, RECORDS_SENT},
            stats::Metrics,
        },
        test_fixture::{
            input::GenericReportTestInput,
            ipa::{
                generate_random_user_records_in_reverse_chronological_order, test_ipa,
                update_expected_output_for_user,
            },
            IpaSecurityModel, Reconstruct, Runner, TestWorld, TestWorldConfig,
        },
    };
    use generic_array::GenericArray;
    use proptest::{
        proptest,
        test_runner::{RngAlgorithm, TestRng},
    };
    use rand::{rngs::StdRng, thread_rng, Rng};
    use rand_core::SeedableRng;
    use typenum::Unsigned;

    #[tokio::test]
    #[allow(clippy::missing_panics_doc)]
    pub async fn semi_honest() {
        const COUNT: usize = 7;
        const PER_USER_CAP: u32 = 3;
        const EXPECTED: &[[u128; 2]] = &[
            [0, 0],
            [1, 2],
            [2, 3],
            [3, 0],
            [4, 0],
            [5, 0],
            [6, 0],
            [7, 0],
        ];
        const MAX_BREAKDOWN_KEY: u32 = 8;
        const ATTRIBUTION_WINDOW_SECONDS: u32 = 0;
        const NUM_MULTI_BITS: u32 = 3;

        let world = TestWorld::default();

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
                    ATTRIBUTION_WINDOW_SECONDS,
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
        const MAX_BREAKDOWN_KEY: u32 = 3;
        const ATTRIBUTION_WINDOW_SECONDS: u32 = 0;
        const NUM_MULTI_BITS: u32 = 3;

        let world = TestWorld::default();

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
                    ATTRIBUTION_WINDOW_SECONDS,
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
        const MAX_BREAKDOWN_KEY: u32 = 7;
        const ATTRIBUTION_WINDOW_SECONDS: u32 = 0;
        const NUM_MULTI_BITS: u32 = 3;

        let world = TestWorld::default();

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
                    ATTRIBUTION_WINDOW_SECONDS,
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
                ipa_malicious::<Fp31, MatchKey, BreakdownKey>(
                    ctx,
                    &input_rows,
                    PER_USER_CAP,
                    MAX_BREAKDOWN_KEY,
                    ATTRIBUTION_WINDOW_SECONDS,
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
    #[allow(clippy::missing_panics_doc)]
    pub async fn random_ipa_check() {
        const MAX_BREAKDOWN_KEY: u32 = 64;
        const MAX_TRIGGER_VALUE: u32 = 5;
        const NUM_USERS: usize = 8;
        const MAX_RECORDS_PER_USER: usize = 8;
        const NUM_MULTI_BITS: u32 = 3;
        const ATTRIBUTION_WINDOW_SECONDS: u32 = 0;
        type TestField = Fp32BitPrime;

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
        let config = TestWorldConfig {
            gateway_config: GatewayConfig::symmetric_buffers::<TestField>(
                raw_data.len().clamp(4, 1024),
            ),
            ..Default::default()
        };

        let world = TestWorld::new_with(config);

        for per_user_cap in [1, 3] {
            let mut expected_results = vec![0_u32; MAX_BREAKDOWN_KEY.try_into().unwrap()];

            for records_for_user in &random_user_records {
                update_expected_output_for_user(
                    records_for_user,
                    &mut expected_results,
                    per_user_cap,
                    ATTRIBUTION_WINDOW_SECONDS,
                );
            }

            test_ipa::<TestField>(
                &world,
                &raw_data,
                &expected_results,
                per_user_cap,
                MAX_BREAKDOWN_KEY,
                ATTRIBUTION_WINDOW_SECONDS,
                IpaSecurityModel::SemiHonest,
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
        a.serialize(GenericArray::from_mut_slice(
            &mut buf[..<IPAInputRow<Fp31, MatchKey, BreakdownKey> as Serializable>::Size::USIZE],
        ));
        b.serialize(GenericArray::from_mut_slice(
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
        const MAX_BREAKDOWN_KEY: u32 = 3;
        const ATTRIBUTION_WINDOW_SECONDS: u32 = 0;
        const NUM_MULTI_BITS: u32 = 3;
        const FIELD_SIZE: u64 = <Fp32BitPrime as Serializable>::Size::U64;

        /// empirical value as of Mar 24, 2023.
        const RECORDS_SENT_SEMI_HONEST_BASELINE_CAP_3: u64 = 14085;
        const BYTES_SENT_SEMI_HONEST_BASELINE_CAP_3: u64 = 46647;

        /// empirical value as of Mar 24, 2023.
        const RECORDS_SENT_MALICIOUS_BASELINE_CAP_3: u64 = 35244;
        const BYTES_SENT_MALICIOUS_BASELINE_CAP_3: u64 = 131_283;

        /// empirical value as of Mar 24, 2023.
        const RECORDS_SENT_SEMI_HONEST_BASELINE_CAP_1: u64 = 10404;
        const BYTES_SENT_SEMI_HONEST_BASELINE_CAP_1: u64 = 31932;

        /// empirical value as of Mar 24, 2023.
        const RECORDS_SENT_MALICIOUS_BASELINE_CAP_1: u64 = 25866;
        const BYTES_SENT_MALICIOUS_BASELINE_CAP_1: u64 = 93780;

        let records: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = ipa_test_input!(
            [
                { match_key: 12345, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { match_key: 12345, is_trigger_report: 0, breakdown_key: 2, trigger_value: 0 },
                { match_key: 68362, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 5 },
                { match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 2 },
                { match_key: 12345, is_trigger_report: 0, breakdown_key: 2, trigger_value: 0 },
                { match_key: 68362, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 3 },
                { match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 4 },
            ];
            (Fp32BitPrime, MatchKey, BreakdownKey)
        );

        for per_user_cap in [1, 3] {
            let world = TestWorld::new_with(TestWorldConfig::default().enable_metrics());

            let _: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = world
                .semi_honest(records.clone(), |ctx, input_rows| async move {
                    ipa::<Fp32BitPrime, MatchKey, BreakdownKey>(
                        ctx,
                        &input_rows,
                        per_user_cap,
                        MAX_BREAKDOWN_KEY,
                        ATTRIBUTION_WINDOW_SECONDS,
                        NUM_MULTI_BITS,
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();

            let snapshot = world.metrics_snapshot();
            let (records_baseline, bytes_baseline) = if per_user_cap == 1 {
                (
                    RECORDS_SENT_SEMI_HONEST_BASELINE_CAP_1,
                    BYTES_SENT_SEMI_HONEST_BASELINE_CAP_1,
                )
            } else {
                (
                    RECORDS_SENT_SEMI_HONEST_BASELINE_CAP_3,
                    BYTES_SENT_SEMI_HONEST_BASELINE_CAP_3,
                )
            };
            assert_baselines(
                &format!("semi-honest IPA (cap = {per_user_cap})"),
                &snapshot,
                [
                    (RECORDS_SENT, records_baseline),
                    (BYTES_SENT, bytes_baseline),
                ],
            );

            let world = TestWorld::new_with(TestWorldConfig::default().enable_metrics());

            let _ = world
                .semi_honest(records.clone(), |ctx, input_rows| async move {
                    ipa_malicious::<Fp32BitPrime, MatchKey, BreakdownKey>(
                        ctx,
                        &input_rows,
                        per_user_cap,
                        MAX_BREAKDOWN_KEY,
                        ATTRIBUTION_WINDOW_SECONDS,
                        NUM_MULTI_BITS,
                    )
                    .await
                    .unwrap()
                })
                .await;

            let snapshot = world.metrics_snapshot();
            let (records_baseline, bytes_baseline) = if per_user_cap == 1 {
                (
                    RECORDS_SENT_MALICIOUS_BASELINE_CAP_1,
                    BYTES_SENT_MALICIOUS_BASELINE_CAP_1,
                )
            } else {
                (
                    RECORDS_SENT_MALICIOUS_BASELINE_CAP_3,
                    BYTES_SENT_MALICIOUS_BASELINE_CAP_3,
                )
            };
            assert_baselines(
                &format!("malicious IPA (cap = {per_user_cap})"),
                &snapshot,
                [
                    (RECORDS_SENT, records_baseline),
                    (BYTES_SENT, bytes_baseline),
                ],
            );
        }
    }

    fn assert_baselines<const N: usize>(
        name: &str,
        snapshot: &Metrics,
        baselines: [(&'static str, u64); N],
    ) {
        for (metric_name, baseline) in baselines {
            let actual = snapshot.get_counter(metric_name);
            assert!(actual <= baseline,
                    "{metric_name} baseline for {name} has DEGRADED! Expected {baseline}, got {actual}.");

            if actual < baseline {
                tracing::warn!("{metric_name} baseline for {name} has improved! Expected {baseline}, got {actual}. \
                Strongly consider adjusting the baseline, so the gains won't be accidentally offset by a regression.");
            }
        }
    }
}
