use crate::{
    error::Error,
    ff::{Field, GaloisField, Gf2, PrimeField, Serializable},
    helpers::{query::IpaQueryConfig, Role},
    protocol::{
        attribution::{
            input::{MCAggregateCreditOutputRow, MCCappedCreditsWithAggregationBit},
            secure_attribution,
        },
        basics::Reshare,
        boolean::RandomBits,
        context::{
            upgrade::IPAModulusConvertedInputRowWrapper, Context, UpgradableContext,
            UpgradedContext, Validator,
        },
        modulus_conversion::{convert_all_bits, convert_all_bits_local},
        sort::{
            apply_sort::apply_sort_permutation,
            generate_permutation::{
                generate_permutation_and_reveal_shuffled, ShuffledPermutationWrapper,
            },
        },
        BasicProtocols, RecordId,
    },
    secret_sharing::{
        replicated::{
            malicious::{DowngradeMalicious, ExtendableField},
            semi_honest::AdditiveShare as Replicated,
            ReplicatedSecretSharing,
        },
        Linear as LinearSecretSharing,
    },
};
use async_trait::async_trait;
use futures::future::try_join4;
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
    AfterConvertAllBits,
    BinaryValidator,
}

impl crate::protocol::step::Step for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::ModulusConversionForMatchKeys => "mod_conv_match_key",
            Self::ModulusConversionForBreakdownKeys => "mod_conv_breakdown_key",
            Self::GenSortPermutationFromMatchKeys => "gen_sort_permutation_from_match_keys",
            Self::ApplySortPermutation => "apply_sort_permutation",
            Self::ApplySortPermutationToMatchKeys => "apply_sort_permutation_to_match_keys",
            Self::AfterConvertAllBits => "after_convert_all_bits",
            Self::BinaryValidator => "binary_validator",
        }
    }
}

pub enum IPAInputRowResharableStep {
    Timestamp,
    MatchKeyShares,
    TriggerBit,
    BreakdownKey,
    TriggerValue,
}

impl crate::protocol::step::Step for IPAInputRowResharableStep {}

impl AsRef<str> for IPAInputRowResharableStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::Timestamp => "timestamp",
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
    pub timestamp: Replicated<F>,
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
    <Replicated<F> as Serializable>::Size: Add<
        <<Replicated<MK> as Serializable>::Size as Add<
            <<Replicated<F> as Serializable>::Size as Add<
                <<Replicated<BK> as Serializable>::Size as Add<
                    <Replicated<F> as Serializable>::Size,
                >>::Output,
            >>::Output,
        >>::Output,
    >,
    <<Replicated<F> as Serializable>::Size as Add<
        <<Replicated<MK> as Serializable>::Size as Add<
            <<Replicated<F> as Serializable>::Size as Add<
                <<Replicated<BK> as Serializable>::Size as Add<
                    <Replicated<F> as Serializable>::Size,
                >>::Output,
            >>::Output,
        >>::Output,
    >>::Output: ArrayLength<u8>,
{
    type Size = <<Replicated<F> as Serializable>::Size as Add<
        <<Replicated<MK> as Serializable>::Size as Add<
            <<Replicated<F> as Serializable>::Size as Add<
                <<Replicated<BK> as Serializable>::Size as Add<
                    <Replicated<F> as Serializable>::Size,
                >>::Output,
            >>::Output,
        >>::Output,
    >>::Output;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        let mk_sz = <Replicated<MK> as Serializable>::Size::USIZE;
        let bk_sz = <Replicated<BK> as Serializable>::Size::USIZE;
        let f_sz = <Replicated<F> as Serializable>::Size::USIZE;

        self.timestamp
            .serialize(GenericArray::from_mut_slice(&mut buf[..f_sz]));
        self.mk_shares
            .serialize(GenericArray::from_mut_slice(&mut buf[f_sz..f_sz + mk_sz]));
        self.is_trigger_bit.serialize(GenericArray::from_mut_slice(
            &mut buf[f_sz + mk_sz..f_sz + mk_sz + f_sz],
        ));
        self.breakdown_key.serialize(GenericArray::from_mut_slice(
            &mut buf[f_sz + mk_sz + f_sz..f_sz + mk_sz + f_sz + bk_sz],
        ));
        self.trigger_value.serialize(GenericArray::from_mut_slice(
            &mut buf[f_sz + mk_sz + f_sz + bk_sz..],
        ));
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        let mk_sz = <Replicated<MK> as Serializable>::Size::USIZE;
        let bk_sz = <Replicated<BK> as Serializable>::Size::USIZE;
        let f_sz = <Replicated<F> as Serializable>::Size::USIZE;

        let timestamp = Replicated::<F>::deserialize(GenericArray::from_slice(&buf[..f_sz]));
        let mk_shares =
            Replicated::<MK>::deserialize(GenericArray::from_slice(&buf[f_sz..f_sz + mk_sz]));
        let is_trigger_bit = Replicated::<F>::deserialize(GenericArray::from_slice(
            &buf[f_sz + mk_sz..f_sz + mk_sz + f_sz],
        ));
        let breakdown_key = Replicated::<BK>::deserialize(GenericArray::from_slice(
            &buf[f_sz + mk_sz + f_sz..f_sz + mk_sz + f_sz + bk_sz],
        ));
        let trigger_value = Replicated::<F>::deserialize(GenericArray::from_slice(
            &buf[f_sz + mk_sz + f_sz + bk_sz..],
        ));
        Self {
            timestamp,
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
    pub timestamp: T,
    pub is_trigger_bit: T,
    pub breakdown_key: Vec<T>,
    pub trigger_value: T,
    _marker: PhantomData<F>,
}

impl<F: Field, T: LinearSecretSharing<F>> IPAModulusConvertedInputRow<F, T> {
    pub fn new(timestamp: T, is_trigger_bit: T, breakdown_key: Vec<T>, trigger_value: T) -> Self {
        Self {
            timestamp,
            is_trigger_bit,
            breakdown_key,
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
        let f_timestamp = self.timestamp.reshare(
            ctx.narrow(&IPAInputRowResharableStep::Timestamp),
            record_id,
            to_helper,
        );
        let f_is_trigger_bit = self.is_trigger_bit.reshare(
            ctx.narrow(&IPAInputRowResharableStep::TriggerBit),
            record_id,
            to_helper,
        );
        let f_breakdown_key = self.breakdown_key.reshare(
            ctx.narrow(&IPAInputRowResharableStep::BreakdownKey),
            record_id,
            to_helper,
        );
        let f_trigger_value = self.trigger_value.reshare(
            ctx.narrow(&IPAInputRowResharableStep::TriggerValue),
            record_id,
            to_helper,
        );

        let (breakdown_key, timestamp, is_trigger_bit, trigger_value) = try_join4(
            f_breakdown_key,
            f_timestamp,
            f_is_trigger_bit,
            f_trigger_value,
        )
        .await?;

        Ok(IPAModulusConvertedInputRow::new(
            timestamp,
            is_trigger_bit,
            breakdown_key,
            trigger_value,
        ))
    }
}

/// Malicious IPA
/// We return `Replicated<F>` as output since there is compute after this and in `aggregate_credit`, last communication operation was sort
/// # Errors
/// Propagates errors from multiplications
/// # Panics
/// Propagates errors from multiplications
#[allow(clippy::too_many_lines)]
pub async fn ipa<'a, C, S, SB, F, MK, BK>(
    sh_ctx: C,
    input_rows: &[IPAInputRow<F, MK, BK>],
    config: IpaQueryConfig,
) -> Result<Vec<MCAggregateCreditOutputRow<F, Replicated<F>, BK>>, Error>
where
    C: UpgradableContext,
    C::UpgradedContext<F>: UpgradedContext<F, Share = S> + RandomBits<F, Share = S>,
    S: LinearSecretSharing<F>
        + BasicProtocols<C::UpgradedContext<F>, F>
        + Reshare<C::UpgradedContext<F>, RecordId>
        + Serializable
        + DowngradeMalicious<Target = Replicated<F>>
        + 'static,
    C::UpgradedContext<Gf2>: UpgradedContext<Gf2, Share = SB>,
    SB: LinearSecretSharing<Gf2>
        + BasicProtocols<C::UpgradedContext<Gf2>, Gf2>
        + DowngradeMalicious<Target = Replicated<Gf2>>
        + 'static,
    F: PrimeField + ExtendableField,
    MK: GaloisField,
    BK: GaloisField,
    ShuffledPermutationWrapper<S, C::UpgradedContext<F>>: DowngradeMalicious<Target = Vec<u32>>,
    MCCappedCreditsWithAggregationBit<F, S>:
        DowngradeMalicious<Target = MCCappedCreditsWithAggregationBit<F, Replicated<F>>>,
    MCAggregateCreditOutputRow<F, S, BK>:
        DowngradeMalicious<Target = MCAggregateCreditOutputRow<F, Replicated<F>, BK>>,
{
    let validator = sh_ctx.clone().validator::<F>();
    let m_ctx = validator.context();

    let (mk_shares, bk_shares): (Vec<_>, Vec<_>) = input_rows
        .iter()
        .map(|x| (x.mk_shares.clone(), x.breakdown_key.clone()))
        .unzip();

    // Match key modulus conversion, and then sort
    let locally_converted = convert_all_bits_local(m_ctx.role(), mk_shares.into_iter());
    let converted_mk_shares = convert_all_bits(
        &m_ctx.narrow(&Step::ModulusConversionForMatchKeys),
        &m_ctx.upgrade(locally_converted).await?,
        MK::BITS,
        config.num_multi_bits,
    )
    .await
    .unwrap();

    //Validate before calling sort with downgraded context
    let converted_mk_shares = validator.validate(converted_mk_shares).await?;

    let sort_permutation = generate_permutation_and_reveal_shuffled(
        sh_ctx.narrow(&Step::GenSortPermutationFromMatchKeys),
        converted_mk_shares.iter(),
    )
    .await
    .unwrap();

    let validator = sh_ctx.narrow(&Step::AfterConvertAllBits).validator();
    let m_ctx = validator.context();

    let gf2_match_key_bits = get_gf2_match_key_bits(input_rows);

    let binary_validator = sh_ctx.narrow(&Step::BinaryValidator).validator::<Gf2>();
    let binary_m_ctx = binary_validator.context();

    let upgraded_gf2_match_key_bits = binary_m_ctx.upgrade(gf2_match_key_bits).await?;

    // Breakdown key modulus conversion
    let mut converted_bk_shares = convert_all_bits(
        &m_ctx.narrow(&Step::ModulusConversionForBreakdownKeys),
        &m_ctx
            .narrow(&Step::ModulusConversionForBreakdownKeys)
            .upgrade(convert_all_bits_local(m_ctx.role(), bk_shares.into_iter()))
            .await?,
        BK::BITS,
        BK::BITS,
    )
    .await
    .unwrap();

    let converted_bk_shares = converted_bk_shares.pop().unwrap();

    let intermediate = input_rows
        .iter()
        .map(|input_row| {
            IPAModulusConvertedInputRowWrapper::new(
                input_row.timestamp.clone(),
                input_row.is_trigger_bit.clone(),
                input_row.trigger_value.clone(),
            )
        })
        .collect::<Vec<_>>();

    let intermediate = m_ctx.upgrade(intermediate).await?;

    let inputs_sans_match_keys = intermediate
        .into_iter()
        .zip(converted_bk_shares)
        .map(|(one_row, bk_shares)| IPAModulusConvertedInputRow::<F, S> {
            timestamp: one_row.timestamp,
            is_trigger_bit: one_row.is_trigger_bit,
            trigger_value: one_row.trigger_value,
            breakdown_key: bk_shares,
            _marker: PhantomData,
        })
        .collect::<Vec<_>>();

    let sorted_rows = apply_sort_permutation(
        m_ctx.narrow(&Step::ApplySortPermutation),
        inputs_sans_match_keys,
        &sort_permutation,
    )
    .await
    .unwrap();

    let sorted_match_keys = apply_sort_permutation(
        binary_m_ctx.narrow(&Step::ApplySortPermutation),
        upgraded_gf2_match_key_bits,
        &sort_permutation,
    )
    .await
    .unwrap();

    secure_attribution(
        sh_ctx,
        validator,
        binary_validator,
        sorted_match_keys,
        sorted_rows,
        config,
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

#[cfg(all(test, not(feature = "shuttle"), feature = "in-memory-infra"))]
pub mod tests {
    use super::{ipa, IPAInputRow};
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime, GaloisField, Serializable},
        helpers::{query::IpaQueryConfig, GatewayConfig},
        ipa_test_input,
        protocol::{BreakdownKey, MatchKey},
        secret_sharing::IntoShares,
        telemetry::{
            metrics::{
                BYTES_SENT, INDEXED_PRSS_GENERATED, RECORDS_SENT, SEQUENTIAL_PRSS_GENERATED,
            },
            stats::Metrics,
        },
        test_fixture::{
            input::GenericReportTestInput,
            ipa::{
                generate_random_user_records_in_reverse_chronological_order, test_ipa,
                update_expected_output_for_user, IpaSecurityModel,
            },
            Reconstruct, Runner, TestWorld, TestWorldConfig,
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
                { timestamp: 0, match_key: 12345, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { timestamp: 0, match_key: 12345, is_trigger_report: 0, breakdown_key: 2, trigger_value: 0 },
                { timestamp: 0, match_key: 68362, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { timestamp: 0, match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 5 },
                { timestamp: 0, match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 2 },
            ];
            (Fp31, MatchKey, BreakdownKey)
        );

        let result: Vec<GenericReportTestInput<_, MatchKey, BreakdownKey>> = world
            .semi_honest(records, |ctx, input_rows| async move {
                ipa::<_, _, _, Fp31, MatchKey, BreakdownKey>(
                    ctx,
                    &input_rows,
                    IpaQueryConfig::new(
                        PER_USER_CAP,
                        MAX_BREAKDOWN_KEY,
                        ATTRIBUTION_WINDOW_SECONDS,
                        NUM_MULTI_BITS,
                    ),
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
        const PER_USER_CAP: u32 = 3;
        const EXPECTED: &[[u128; 2]] = &[[0, 0], [1, 2], [2, 3]];
        const MAX_BREAKDOWN_KEY: u32 = 3;
        const ATTRIBUTION_WINDOW_SECONDS: u32 = 0;
        const NUM_MULTI_BITS: u32 = 3;

        let world = TestWorld::default();

        let records: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> = ipa_test_input!(
            [
                { timestamp: 1, match_key: 12345, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { timestamp: 2, match_key: 12345, is_trigger_report: 0, breakdown_key: 2, trigger_value: 0 },
                { timestamp: 3, match_key: 68362, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { timestamp: 4, match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 5 },
                { timestamp: 5, match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 2 },
            ];
            (Fp31, MatchKey, BreakdownKey)
        );

        let result: Vec<GenericReportTestInput<_, MatchKey, BreakdownKey>> = world
            .semi_honest(records, |ctx, input_rows| async move {
                ipa::<_, _, _, _, MatchKey, BreakdownKey>(
                    ctx,
                    &input_rows,
                    IpaQueryConfig::new(
                        PER_USER_CAP,
                        MAX_BREAKDOWN_KEY,
                        ATTRIBUTION_WINDOW_SECONDS,
                        NUM_MULTI_BITS,
                    ),
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
    async fn semi_honest_with_attribution_window() {
        const PER_USER_CAP: u32 = 3;
        const EXPECTED: &[[u128; 2]] = &[
            [0, 0],
            [1, 0],
            [2, 3],
            [3, 0],
            [4, 0],
            [5, 0],
            [6, 0],
            [7, 0],
        ];
        const MAX_BREAKDOWN_KEY: u32 = 8;
        const ATTRIBUTION_WINDOW_SECONDS: u32 = 10;
        const NUM_MULTI_BITS: u32 = 3;

        let world = TestWorld::default();

        let records: Vec<GenericReportTestInput<_, MatchKey, BreakdownKey>> = ipa_test_input!(
            [
                { timestamp: 0, match_key: 12345, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { timestamp: 2, match_key: 12345, is_trigger_report: 0, breakdown_key: 2, trigger_value: 0 }, // A
                { timestamp: 3, match_key: 68362, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 }, // B
                { timestamp: 12, match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 5 }, // Attributed to A (12 - 2)
                { timestamp: 15, match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 2 }, // Not Attributed to B because it's outside the window (15 - 3)
            ];
            (Fp31, MatchKey, BreakdownKey)
        );

        let result: Vec<GenericReportTestInput<_, MatchKey, BreakdownKey>> = world
            .semi_honest(records, |ctx, input_rows| async move {
                ipa::<_, _, _, Fp31, MatchKey, BreakdownKey>(
                    ctx,
                    &input_rows,
                    IpaQueryConfig::new(
                        PER_USER_CAP,
                        MAX_BREAKDOWN_KEY,
                        ATTRIBUTION_WINDOW_SECONDS,
                        NUM_MULTI_BITS,
                    ),
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
    async fn malicious_with_attribution_window() {
        const PER_USER_CAP: u32 = 3;
        const EXPECTED: &[[u128; 2]] = &[[0, 0], [1, 0], [2, 3]];
        const MAX_BREAKDOWN_KEY: u32 = 3;
        const ATTRIBUTION_WINDOW_SECONDS: u32 = 10;
        const NUM_MULTI_BITS: u32 = 3;

        let world = TestWorld::default();

        let records: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> = ipa_test_input!(
            [
                { timestamp: 0, match_key: 12345, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { timestamp: 2, match_key: 12345, is_trigger_report: 0, breakdown_key: 2, trigger_value: 0 }, // A
                { timestamp: 3, match_key: 68362, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 }, // B
                { timestamp: 12, match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 5 }, // Attributed to A (12 - 2)
                { timestamp: 15, match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 2 }, // Not Attributed to B because it's outside the window (15 - 3)
            ];
            (Fp31, MatchKey, BreakdownKey)
        );

        let result: Vec<GenericReportTestInput<_, MatchKey, BreakdownKey>> = world
            .malicious(records, |ctx, input_rows| async move {
                ipa::<_, _, _, _, MatchKey, BreakdownKey>(
                    ctx,
                    &input_rows,
                    IpaQueryConfig::new(
                        PER_USER_CAP,
                        MAX_BREAKDOWN_KEY,
                        ATTRIBUTION_WINDOW_SECONDS,
                        NUM_MULTI_BITS,
                    ),
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
                { timestamp: 0, match_key: 12345, is_trigger_report: 0, breakdown_key: 0, trigger_value: 0 }, // Irrelevant
                { timestamp: 0, match_key: 12345, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 }, // A
                { timestamp: 0, match_key: 68362, is_trigger_report: 0, breakdown_key: 2, trigger_value: 0 }, // B
                { timestamp: 0, match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 0 }, // This will be attributed to A
                { timestamp: 0, match_key: 77777, is_trigger_report: 1, breakdown_key: 1, trigger_value: 0 }, // Irrelevant
                { timestamp: 0, match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 0 }, // This will be attributed to B, but will be capped
                { timestamp: 0, match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 0 }, // Irrelevant
                { timestamp: 0, match_key: 68362, is_trigger_report: 0, breakdown_key: 3, trigger_value: 0 }, // C
                { timestamp: 0, match_key: 77777, is_trigger_report: 0, breakdown_key: 4, trigger_value: 0 }, // Irrelevant
                { timestamp: 0, match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 0 }, // This will be attributed to C, but will be capped
                { timestamp: 0, match_key: 81818, is_trigger_report: 0, breakdown_key: 6, trigger_value: 0 }, // E
                { timestamp: 0, match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 0 }, // Irrelevant
                { timestamp: 0, match_key: 81818, is_trigger_report: 1, breakdown_key: 0, trigger_value: 0 }, // This will be attributed to E
                { timestamp: 0, match_key: 68362, is_trigger_report: 0, breakdown_key: 5, trigger_value: 0 }, // D
                { timestamp: 0, match_key: 99999, is_trigger_report: 0, breakdown_key: 6, trigger_value: 0 }, // Irrelevant
                { timestamp: 0, match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 0 }, // This will be attributed to D

            ];
            (Fp31, MatchKey, BreakdownKey)
        );

        let result: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> = world
            .semi_honest(records.clone(), |ctx, input_rows| async move {
                ipa::<_, _, _, Fp31, MatchKey, BreakdownKey>(
                    ctx,
                    &input_rows,
                    IpaQueryConfig::new(
                        PER_USER_CAP,
                        MAX_BREAKDOWN_KEY,
                        ATTRIBUTION_WINDOW_SECONDS,
                        NUM_MULTI_BITS,
                    ),
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
                ipa::<_, _, _, Fp31, MatchKey, BreakdownKey>(
                    ctx,
                    &input_rows,
                    IpaQueryConfig::new(
                        PER_USER_CAP,
                        MAX_BREAKDOWN_KEY,
                        ATTRIBUTION_WINDOW_SECONDS,
                        NUM_MULTI_BITS,
                    ),
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
    async fn cap_of_one_with_attribution_window() {
        const PER_USER_CAP: u32 = 1;
        const EXPECTED: &[[u128; 2]] = &[[0, 0], [1, 1], [2, 0], [3, 1], [4, 0], [5, 0], [6, 1]];
        const MAX_BREAKDOWN_KEY: u32 = 7;
        const ATTRIBUTION_WINDOW_SECONDS: u32 = 3;
        const NUM_MULTI_BITS: u32 = 3;

        let world = TestWorld::default();

        let records: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> = ipa_test_input!(
            [
                { timestamp: 0, match_key: 12345, is_trigger_report: 0, breakdown_key: 0, trigger_value: 0 }, // Irrelevant
                { timestamp: 1, match_key: 12345, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 }, // A
                { timestamp: 2, match_key: 68362, is_trigger_report: 0, breakdown_key: 2, trigger_value: 0 }, // B
                { timestamp: 3, match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 0 }, // This will be attributed to A
                { timestamp: 4, match_key: 77777, is_trigger_report: 1, breakdown_key: 1, trigger_value: 0 }, // Irrelevant
                { timestamp: 5, match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 0 }, // This will be attributed to B, but will be capped
                { timestamp: 6, match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 0 }, // Irrelevant
                { timestamp: 7, match_key: 68362, is_trigger_report: 0, breakdown_key: 3, trigger_value: 0 }, // C
                { timestamp: 8, match_key: 77777, is_trigger_report: 0, breakdown_key: 4, trigger_value: 0 }, // Irrelevant
                { timestamp: 9, match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 0 }, // This will be attributed to C since TE corresponding to D is expired
                { timestamp: 10, match_key: 81818, is_trigger_report: 0, breakdown_key: 6, trigger_value: 0 }, // E
                { timestamp: 11, match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 0 }, // Irrelevant
                { timestamp: 12, match_key: 81818, is_trigger_report: 1, breakdown_key: 0, trigger_value: 0 }, // This will be attributed to E
                { timestamp: 13, match_key: 68362, is_trigger_report: 0, breakdown_key: 5, trigger_value: 0 }, // D
                { timestamp: 14, match_key: 99999, is_trigger_report: 0, breakdown_key: 6, trigger_value: 0 }, // Irrelevant
                { timestamp: 17, match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 0 }, // This will NOT be attributed to D because it exceeds the attribution window (time_delta=4)
            ];
            (Fp31, MatchKey, BreakdownKey)
        );

        let result: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> = world
            .semi_honest(records.clone(), |ctx, input_rows| async move {
                ipa::<_, _, _, Fp31, MatchKey, BreakdownKey>(
                    ctx,
                    &input_rows,
                    IpaQueryConfig::new(
                        PER_USER_CAP,
                        MAX_BREAKDOWN_KEY,
                        ATTRIBUTION_WINDOW_SECONDS,
                        NUM_MULTI_BITS,
                    ),
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
                ipa::<_, _, _, Fp31, MatchKey, BreakdownKey>(
                    ctx,
                    &input_rows,
                    IpaQueryConfig::new(
                        PER_USER_CAP,
                        MAX_BREAKDOWN_KEY,
                        ATTRIBUTION_WINDOW_SECONDS,
                        NUM_MULTI_BITS,
                    ),
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
        const ATTRIBUTION_WINDOW_SECONDS: u32 = 86_400;
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
            gateway_config: GatewayConfig::new(raw_data.len().clamp(4, 1024)),
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
                IpaQueryConfig::new(
                    per_user_cap,
                    MAX_BREAKDOWN_KEY,
                    ATTRIBUTION_WINDOW_SECONDS,
                    NUM_MULTI_BITS,
                ),
                IpaSecurityModel::SemiHonest,
            )
            .await;
        }
    }

    /// Test for the "wrapping-add" attack (issue #520).
    #[tokio::test]
    #[allow(clippy::missing_panics_doc)]
    pub async fn random_wrapping_add_attack() {
        const PER_USER_CAP: u32 = 15;
        const MAX_BREAKDOWN_KEY: u32 = 8;
        const ATTRIBUTION_WINDOW_SECONDS: u32 = 0;
        const NUM_MULTI_BITS: u32 = 3;
        const RECORD_COUNT: usize = 8;

        let random_seed = thread_rng().gen();
        println!("Using random seed: {random_seed}");
        let mut rng = StdRng::seed_from_u64(random_seed);
        let mut records = Vec::with_capacity(RECORD_COUNT * 2);

        // Generate 8 pairs of (source event, trigger event) tuple, each having a random trigger_value between [4, 31).
        // This ensures there's at least one wrap around at user-level, and catch if the contribution ever exceeds the cap.
        for _ in 0..RECORD_COUNT {
            let mut record = ipa_test_input!(
                [
                    { timestamp: 0, match_key: 11111, is_trigger_report: 0, breakdown_key: rng.gen_range(0..MAX_BREAKDOWN_KEY), trigger_value: 0 },
                    { timestamp: 0, match_key: 11111, is_trigger_report: 1, breakdown_key: 0, trigger_value: rng.gen_range(4..31) },
                ];
                (Fp31, MatchKey, BreakdownKey)
            );
            records.append(&mut record);
        }

        let world = TestWorld::default();
        let result: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> = world
            .semi_honest(records, |ctx, input_rows| async move {
                ipa::<_, _, _, Fp31, MatchKey, BreakdownKey>(
                    ctx,
                    &input_rows,
                    IpaQueryConfig::new(
                        PER_USER_CAP,
                        MAX_BREAKDOWN_KEY,
                        ATTRIBUTION_WINDOW_SECONDS,
                        NUM_MULTI_BITS,
                    ),
                )
                .await
                .unwrap()
            })
            .await
            .reconstruct();

        let trigger_values = result
            .into_iter()
            .map(|x| x.trigger_value.as_u128())
            .collect::<Vec<_>>();
        assert_eq!(MAX_BREAKDOWN_KEY as usize, trigger_values.len());
        println!("actual results: {trigger_values:#?}");

        // Check that
        //   * the contribution never exceeds the cap.
        //   * the sum of all contributions = cap.
        assert!(trigger_values
            .iter()
            .all(|v| *v <= u128::from(PER_USER_CAP)));
        assert_eq!(
            u128::from(PER_USER_CAP),
            trigger_values.into_iter().reduce(|acc, x| acc + x).unwrap()
        );
    }

    fn serde_internal(
        timestamp: u128,
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
                { timestamp: timestamp, match_key: match_key, is_trigger_report: trigger_bit, breakdown_key: breakdown_key, trigger_value: trigger_value },
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
        fn serde(timestamp in 0..u128::MAX, match_key in 0..u64::MAX, trigger_bit in 0..u128::MAX, breakdown_key in 0..u128::MAX, trigger_value in 0..u128::MAX, seed in 0..u128::MAX) {
            serde_internal(timestamp, match_key, trigger_bit, breakdown_key, trigger_value, seed);
        }
    }

    /// Ensures that our communication and PRSS numbers don't go above the baseline.
    /// Prints a warning if they are currently below, so someone needs to adjust the baseline
    /// inside this test.
    ///
    /// It is possible to increase the number too if there is a good reason for it. This is a
    /// "catch all" type of test to make sure we don't miss an accidental regression.
    mod baselines {
        use super::*;
        use crate::test_fixture::ipa::IpaSecurityModel::{Malicious, SemiHonest};

        const MAX_BREAKDOWN_KEY: u32 = 3;
        const ATTRIBUTION_WINDOW_SECONDS: u32 = 600;
        const NUM_MULTI_BITS: u32 = 3;

        fn cap_one() -> IpaQueryConfig {
            IpaQueryConfig {
                per_user_credit_cap: 1,
                max_breakdown_key: MAX_BREAKDOWN_KEY,
                attribution_window_seconds: ATTRIBUTION_WINDOW_SECONDS,
                num_multi_bits: NUM_MULTI_BITS,
            }
        }

        fn cap_three() -> IpaQueryConfig {
            IpaQueryConfig {
                per_user_credit_cap: 3,
                max_breakdown_key: MAX_BREAKDOWN_KEY,
                attribution_window_seconds: ATTRIBUTION_WINDOW_SECONDS,
                num_multi_bits: NUM_MULTI_BITS,
            }
        }

        fn generate_input<F: Field>() -> Vec<GenericReportTestInput<F, MatchKey, BreakdownKey>> {
            ipa_test_input!(
                [
                    { timestamp: 100, match_key: 12345, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                    { timestamp: 200, match_key: 12345, is_trigger_report: 0, breakdown_key: 2, trigger_value: 0 },
                    { timestamp: 300, match_key: 68362, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                    { timestamp: 400, match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 5 },
                    { timestamp: 500, match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 2 },
                    { timestamp: 600, match_key: 12345, is_trigger_report: 0, breakdown_key: 2, trigger_value: 0 },
                    { timestamp: 700, match_key: 68362, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                    { timestamp: 800, match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 3 },
                    { timestamp: 900, match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 4 },
                ];
                (F, MatchKey, BreakdownKey)
            )
        }

        /// Metrics that reflect IPA performance
        #[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
        struct PerfMetrics {
            /// Expected number of records sent between all helpers.
            records_sent: u64,
            /// Same as above, but bytes.
            bytes_sent: u64,
            /// Indexed random values generated by all helpers.
            indexed_prss: u64,
            /// Random values produced by PRSS random generators.
            seq_prss: u64,
        }

        impl PerfMetrics {
            pub fn from_snapshot(snapshot: &Metrics) -> Self {
                Self {
                    records_sent: snapshot.get_counter(RECORDS_SENT),
                    bytes_sent: snapshot.get_counter(BYTES_SENT),
                    indexed_prss: snapshot.get_counter(INDEXED_PRSS_GENERATED),
                    seq_prss: snapshot.get_counter(SEQUENTIAL_PRSS_GENERATED),
                }
            }
        }

        /// Executes malicious or semi-honest IPA and validates that performance metrics stay
        /// within the boundaries defined in `expected`.
        async fn run_and_verify(
            query_config: IpaQueryConfig,
            mode: IpaSecurityModel,
            expected: PerfMetrics,
        ) {
            let records = generate_input();
            let test_config = TestWorldConfig::default().enable_metrics().with_seed(0);
            let world = TestWorld::new_with(test_config);
            let _: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = match mode {
                Malicious => world.malicious(records, |ctx, input_rows| async move {
                    ipa::<_, _, _, Fp32BitPrime, MatchKey, BreakdownKey>(
                        ctx,
                        &input_rows,
                        query_config,
                    )
                    .await
                    .unwrap()
                }),
                SemiHonest => world.semi_honest(records, |ctx, input_rows| async move {
                    ipa::<_, _, _, Fp32BitPrime, MatchKey, BreakdownKey>(
                        ctx,
                        &input_rows,
                        query_config,
                    )
                    .await
                    .unwrap()
                }),
            }
            .await
            .reconstruct();

            let actual = PerfMetrics::from_snapshot(&world.metrics_snapshot());
            assert!(
                expected >= actual,
                "{mode:?} IPA performance has degraded. Expected: {expected:?} >= {actual:?}"
            );

            if expected > actual {
                tracing::warn!("Baseline for {mode:?} IPA has improved! Expected {expected:?}, got {actual:?}. \
                Strongly consider adjusting the baseline, so the gains won't be accidentally offset by a regression.");
            }
        }

        #[tokio::test]
        async fn semi_honest_cap_1() {
            run_and_verify(
                cap_one(),
                SemiHonest,
                PerfMetrics {
                    records_sent: 14_589,
                    bytes_sent: 49_068,
                    indexed_prss: 19_473,
                    seq_prss: 1124,
                },
            )
            .await;
        }

        #[tokio::test]
        async fn semi_honest_cap_3() {
            run_and_verify(
                cap_three(),
                SemiHonest,
                PerfMetrics {
                    records_sent: 21_936,
                    bytes_sent: 78_456,
                    indexed_prss: 28_494,
                    seq_prss: 1124,
                },
            )
            .await;
        }

        #[tokio::test]
        async fn malicious_cap_1() {
            run_and_verify(
                cap_one(),
                Malicious,
                PerfMetrics {
                    records_sent: 36_714,
                    bytes_sent: 137_568,
                    indexed_prss: 76_014,
                    seq_prss: 1098,
                },
            )
            .await;
        }

        #[tokio::test]
        async fn malicious_cap_3() {
            run_and_verify(
                cap_three(),
                Malicious,
                PerfMetrics {
                    records_sent: 55_440,
                    bytes_sent: 212_472,
                    indexed_prss: 113_337,
                    seq_prss: 1098,
                },
            )
            .await;
        }
    }
}
