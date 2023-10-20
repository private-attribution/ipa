use std::{iter::zip, marker::PhantomData, ops::Add};

use async_trait::async_trait;
use futures::{
    future::{try_join, try_join3},
    stream::iter as stream_iter,
};
use generic_array::{ArrayLength, GenericArray};
use ipa_macros::Step;
use typenum::Unsigned;

use crate::{
    error::Error,
    ff::{Field, GaloisField, Gf2, PrimeField, Serializable},
    helpers::{query::IpaQueryConfig, Role},
    protocol::{
        attribution::secure_attribution,
        basics::Reshare,
        context::{
            Context, UpgradableContext, UpgradeContext, UpgradeToMalicious, UpgradedContext,
            Validator,
        },
        modulus_conversion::BitConversionTriple,
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
        BitDecomposed, Linear as LinearSecretSharing, LinearRefOps,
    },
};

#[derive(Step)]
pub(crate) enum Step {
    GenSortPermutationFromMatchKeys,
    ApplySortPermutation,
    AfterConvertAllBits,
    UpgradeMatchKeyBits,
    UpgradeBreakdownKeyBits,
    BinaryValidator,
}

#[derive(Step)]
pub(crate) enum IPAInputRowResharableStep {
    Timestamp,
    MatchKeyShares,
    TriggerBit,
    BreakdownKey,
    TriggerValue,
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
    >>::Output: ArrayLength,
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

pub struct ArithmeticallySharedIPAInputs<F: Field, S: LinearSecretSharing<F>> {
    pub timestamp: S,
    pub is_trigger_bit: S,
    pub trigger_value: S,
    _marker: PhantomData<F>,
}

impl<F: Field, S: LinearSecretSharing<F>> ArithmeticallySharedIPAInputs<F, S> {
    pub fn new(timestamp: S, is_trigger_bit: S, trigger_value: S) -> Self {
        Self {
            timestamp,
            is_trigger_bit,
            trigger_value,
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<F, S, C> Reshare<C, RecordId> for ArithmeticallySharedIPAInputs<F, S>
where
    F: Field,
    S: LinearSecretSharing<F> + Reshare<C, RecordId>,
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
        let f_trigger_value = self.trigger_value.reshare(
            ctx.narrow(&IPAInputRowResharableStep::TriggerValue),
            record_id,
            to_helper,
        );

        let (timestamp, is_trigger_bit, trigger_value) =
            try_join3(f_timestamp, f_is_trigger_bit, f_trigger_value).await?;

        Ok(ArithmeticallySharedIPAInputs::new(
            timestamp,
            is_trigger_bit,
            trigger_value,
        ))
    }
}

pub struct BinarySharedIPAInputs<T: LinearSecretSharing<Gf2>> {
    pub match_key: BitDecomposed<T>,
    pub breakdown_key: BitDecomposed<T>,
}

impl<T: LinearSecretSharing<Gf2>> BinarySharedIPAInputs<T> {
    #[must_use]
    pub fn new(match_key: BitDecomposed<T>, breakdown_key: BitDecomposed<T>) -> Self {
        Self {
            match_key,
            breakdown_key,
        }
    }
}

#[async_trait]
impl<T, C> Reshare<C, RecordId> for BinarySharedIPAInputs<T>
where
    T: LinearSecretSharing<Gf2> + Reshare<C, RecordId>,
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
        let (match_key, breakdown_key) = try_join(
            self.match_key.reshare(
                ctx.narrow(&IPAInputRowResharableStep::MatchKeyShares),
                record_id,
                to_helper,
            ),
            self.breakdown_key.reshare(
                ctx.narrow(&IPAInputRowResharableStep::BreakdownKey),
                record_id,
                to_helper,
            ),
        )
        .await?;

        Ok(BinarySharedIPAInputs::new(match_key, breakdown_key))
    }
}

/// IPA Protocol
///
/// We return `Replicated<F>` as output since there is compute after this and in `aggregate_credit`, last communication operation was sort.
/// # Errors
/// Propagates errors from multiplications
/// # Panics
/// Propagates errors from multiplications
#[allow(clippy::too_many_lines)]
pub async fn ipa<'a, C, S, SB, F, MK, BK>(
    sh_ctx: C,
    input_rows: &[IPAInputRow<F, MK, BK>],
    config: IpaQueryConfig,
) -> Result<Vec<Replicated<F>>, Error>
where
    C: UpgradableContext,
    C::UpgradedContext<F>: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F>
        + BasicProtocols<C::UpgradedContext<F>, F>
        + Reshare<C::UpgradedContext<F>, RecordId>
        + Serializable
        + DowngradeMalicious<Target = Replicated<F>>
        + 'static,
    for<'r> &'r S: LinearRefOps<'r, S, F>,
    C::UpgradedContext<Gf2>: UpgradedContext<Gf2, Share = SB>,
    SB: LinearSecretSharing<Gf2>
        + BasicProtocols<C::UpgradedContext<Gf2>, Gf2>
        + DowngradeMalicious<Target = Replicated<Gf2>>
        + 'static,
    for<'r> &'r SB: LinearRefOps<'r, SB, Gf2>,
    F: PrimeField + ExtendableField,
    MK: GaloisField,
    BK: GaloisField,
    ShuffledPermutationWrapper<S, C::UpgradedContext<F>>: DowngradeMalicious<Target = Vec<u32>>,
    for<'u> UpgradeContext<'u, C::UpgradedContext<F>, F, RecordId>: UpgradeToMalicious<'u, BitConversionTriple<Replicated<F>>, BitConversionTriple<S>>
        + UpgradeToMalicious<
            'u,
            ArithmeticallySharedIPAInputs<F, Replicated<F>>,
            ArithmeticallySharedIPAInputs<F, S>,
        >,
{
    // TODO: We are sorting, which suggests there's limited value in trying to stream the input.
    // However, we immediately copy the complete input into separate vectors for different pieces
    // (MK, BK, credit), so streaming could still be beneficial.

    let mk_shares: Vec<_> = input_rows.iter().map(|x| x.mk_shares.clone()).collect();

    let sort_permutation = generate_permutation_and_reveal_shuffled(
        sh_ctx.narrow(&Step::GenSortPermutationFromMatchKeys),
        stream_iter(mk_shares),
        config.num_multi_bits,
        MK::BITS,
    )
    .await
    .unwrap();

    let validator = sh_ctx.narrow(&Step::AfterConvertAllBits).validator();
    let m_ctx = validator.context();

    let gf2_match_key_bits = get_gf2_match_key_bits(input_rows);
    let gf2_breakdown_key_bits = get_gf2_breakdown_key_bits(input_rows);

    let binary_validator = sh_ctx.narrow(&Step::BinaryValidator).validator::<Gf2>();
    let binary_m_ctx = binary_validator.context();

    let (upgraded_gf2_match_key_bits, upgraded_gf2_breakdown_key_bits) = try_join(
        binary_m_ctx
            .narrow(&Step::UpgradeMatchKeyBits)
            .upgrade(gf2_match_key_bits),
        binary_m_ctx
            .narrow(&Step::UpgradeBreakdownKeyBits)
            .upgrade(gf2_breakdown_key_bits),
    )
    .await?;

    let arithmetically_shared_values = input_rows
        .iter()
        .map(|input_row| {
            ArithmeticallySharedIPAInputs::new(
                input_row.timestamp.clone(),
                input_row.is_trigger_bit.clone(),
                input_row.trigger_value.clone(),
            )
        })
        .collect::<Vec<_>>();

    let arithmetically_shared_values = m_ctx.upgrade(arithmetically_shared_values).await?;

    let binary_shared_values = zip(upgraded_gf2_match_key_bits, upgraded_gf2_breakdown_key_bits)
        .map(|(match_key, breakdown_key)| BinarySharedIPAInputs::new(match_key, breakdown_key))
        .collect::<Vec<_>>();

    let (arithmetically_shared_values, binary_shared_values) = try_join(
        apply_sort_permutation(
            m_ctx.narrow(&Step::ApplySortPermutation),
            arithmetically_shared_values,
            &sort_permutation,
        ),
        apply_sort_permutation(
            binary_m_ctx.narrow(&Step::ApplySortPermutation),
            binary_shared_values,
            &sort_permutation,
        ),
    )
    .await?;

    secure_attribution(
        validator,
        binary_validator,
        arithmetically_shared_values,
        binary_shared_values,
        config,
    )
    .await
}

fn get_gf2_match_key_bits<F, MK, BK>(
    input_rows: &[IPAInputRow<F, MK, BK>],
) -> Vec<BitDecomposed<Replicated<Gf2>>>
where
    F: PrimeField,
    MK: GaloisField,
    BK: GaloisField,
{
    input_rows
        .iter()
        .map(|row| {
            BitDecomposed::decompose(MK::BITS, |i| {
                Replicated::new(
                    Gf2::truncate_from(row.mk_shares.left()[i]),
                    Gf2::truncate_from(row.mk_shares.right()[i]),
                )
            })
        })
        .collect::<Vec<_>>()
}

fn get_gf2_breakdown_key_bits<F, MK, BK>(
    input_rows: &[IPAInputRow<F, MK, BK>],
) -> Vec<BitDecomposed<Replicated<Gf2>>>
where
    F: PrimeField,
    MK: GaloisField,
    BK: GaloisField,
{
    input_rows
        .iter()
        .map(|row| {
            BitDecomposed::decompose(BK::BITS, |i| {
                Replicated::new(
                    Gf2::truncate_from(row.breakdown_key.left()[i]),
                    Gf2::truncate_from(row.breakdown_key.right()[i]),
                )
            })
        })
        .collect::<Vec<_>>()
}

#[cfg(all(test, any(unit_test, feature = "shuttle")))]
pub mod tests {
    use std::num::NonZeroU32;

    use super::ipa;
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime},
        helpers::{query::IpaQueryConfig, GatewayConfig},
        ipa_test_input,
        protocol::{BreakdownKey, MatchKey},
        rand::{thread_rng, Rng},
        test_executor::{run, run_with},
        test_fixture::{
            input::GenericReportTestInput,
            ipa::{ipa_in_the_clear, test_ipa, IpaSecurityModel},
            logging, EventGenerator, EventGeneratorConfig, Reconstruct, Runner, TestWorld,
            TestWorldConfig,
        },
    };

    #[test]
    fn semi_honest() {
        const PER_USER_CAP: u32 = 3;
        const EXPECTED: &[u128] = &[0, 2, 3, 0, 0, 0, 0, 0];
        const MAX_BREAKDOWN_KEY: u32 = 8;
        const NUM_MULTI_BITS: u32 = 3;

        run(|| async {
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

            let result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    ipa::<_, _, _, Fp31, MatchKey, BreakdownKey>(
                        ctx,
                        &input_rows,
                        IpaQueryConfig::no_window(PER_USER_CAP, MAX_BREAKDOWN_KEY, NUM_MULTI_BITS),
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            assert_eq!(result, EXPECTED);
        });
    }

    #[test]
    fn malicious() {
        const PER_USER_CAP: u32 = 3;
        const EXPECTED: &[u128] = &[0, 2, 3];
        const MAX_BREAKDOWN_KEY: u32 = 3;
        const NUM_MULTI_BITS: u32 = 3;

        run(|| async {
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

            let result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    ipa::<_, _, _, _, MatchKey, BreakdownKey>(
                        ctx,
                        &input_rows,
                        IpaQueryConfig::no_window(PER_USER_CAP, MAX_BREAKDOWN_KEY, NUM_MULTI_BITS),
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            assert_eq!(result, EXPECTED);
        });
    }

    #[test]
    fn semi_honest_with_attribution_window() {
        const PER_USER_CAP: u32 = 3;
        const EXPECTED: &[u128] = &[0, 0, 3, 0, 0, 0, 0, 0];
        const MAX_BREAKDOWN_KEY: u32 = 8;
        const ATTRIBUTION_WINDOW_SECONDS: u32 = 10;
        const NUM_MULTI_BITS: u32 = 3;

        run(|| async {
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

            let result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
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
            assert_eq!(result, EXPECTED);
        });
    }

    #[test]
    fn malicious_with_attribution_window() {
        const PER_USER_CAP: u32 = 3;
        const EXPECTED: &[u128] = &[0, 0, 3];
        const MAX_BREAKDOWN_KEY: u32 = 3;
        const ATTRIBUTION_WINDOW_SECONDS: u32 = 10;
        const NUM_MULTI_BITS: u32 = 3;

        run_with::<_, _, 10>(|| async {
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

            let result: Vec<_> = world
                .malicious(records.into_iter(), |ctx, input_rows| async move {
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
            assert_eq!(result, EXPECTED);
        });
    }

    #[test]
    fn cap_of_one() {
        const PER_USER_CAP: u32 = 1;
        const EXPECTED: &[u128] = &[0, 1, 0, 0, 0, 1, 1];
        const MAX_BREAKDOWN_KEY: u32 = 7;
        const NUM_MULTI_BITS: u32 = 3;

        run_with::<_, _, 10>(|| async {
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

            let result: Vec<_> = world
                .semi_honest(records.clone().into_iter(), |ctx, input_rows| async move {
                    ipa::<_, _, _, Fp31, MatchKey, BreakdownKey>(
                        ctx,
                        &input_rows,
                        IpaQueryConfig::no_window(PER_USER_CAP, MAX_BREAKDOWN_KEY, NUM_MULTI_BITS),
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            assert_eq!(result, EXPECTED);

            let result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    ipa::<_, _, _, Fp31, MatchKey, BreakdownKey>(
                        ctx,
                        &input_rows,
                        IpaQueryConfig::no_window(PER_USER_CAP, MAX_BREAKDOWN_KEY, NUM_MULTI_BITS),
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            assert_eq!(result, EXPECTED);
        });
    }

    #[test]
    fn cap_of_one_with_attribution_window() {
        const PER_USER_CAP: u32 = 1;
        const EXPECTED: &[u128] = &[0, 1, 0, 1, 0, 0, 1];
        const MAX_BREAKDOWN_KEY: u32 = 7;
        const ATTRIBUTION_WINDOW_SECONDS: u32 = 3;
        const NUM_MULTI_BITS: u32 = 3;

        run_with::<_, _, 10>(|| async {
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

            let world = TestWorld::default();
            let result: Vec<_> = world
                .semi_honest(records.clone().into_iter(), |ctx, input_rows| async move {
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
            assert_eq!(result, EXPECTED);

            let result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
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
            assert_eq!(result, EXPECTED);
        });
    }

    #[test]
    fn random_semihonest_check() {
        run_with::<_, _, 10>(|| async {
            random_ipa_check(IpaSecurityModel::SemiHonest).await;
        });
    }

    #[test]
    fn random_malicious_check() {
        run_with::<_, _, 4>(|| async {
            random_ipa_check(IpaSecurityModel::Malicious).await;
        });
    }

    async fn random_ipa_check(security: IpaSecurityModel) {
        const MAX_BREAKDOWN_KEY: u32 = 32;
        const MAX_TRIGGER_VALUE: u32 = 5;
        const NUM_USERS: u32 = 8;
        const MAX_RECORDS_PER_USER: u32 = 8;
        const NUM_MULTI_BITS: u32 = 3;
        const ATTRIBUTION_WINDOW_SECONDS: Option<NonZeroU32> = NonZeroU32::new(86_400);
        type TestField = Fp32BitPrime;
        logging::setup();

        // shuttle does not like when it is more than 5 - too many steps for its scheduler
        let max_events = if cfg!(feature = "shuttle") {
            match security {
                IpaSecurityModel::SemiHonest => 5,
                IpaSecurityModel::Malicious => 3,
            }
        } else {
            NUM_USERS * MAX_RECORDS_PER_USER
        };
        let raw_data = EventGenerator::with_config(
            rand::thread_rng(),
            EventGeneratorConfig::new(
                u64::from(NUM_USERS),
                MAX_TRIGGER_VALUE,
                MAX_BREAKDOWN_KEY,
                MAX_RECORDS_PER_USER,
            ),
        )
        .take(usize::try_from(max_events).unwrap())
        .collect::<Vec<_>>();

        for per_user_cap in [1, 3] {
            let expected_results = ipa_in_the_clear(
                &raw_data,
                per_user_cap,
                ATTRIBUTION_WINDOW_SECONDS,
                MAX_BREAKDOWN_KEY,
            );

            let config = TestWorldConfig {
                gateway_config: GatewayConfig::new(raw_data.len().clamp(4, 1024)),
                ..Default::default()
            };
            let world = TestWorld::new_with(config);
            test_ipa::<TestField>(
                &world,
                &raw_data,
                &expected_results,
                IpaQueryConfig {
                    per_user_credit_cap: per_user_cap,
                    max_breakdown_key: MAX_BREAKDOWN_KEY,
                    attribution_window_seconds: ATTRIBUTION_WINDOW_SECONDS,
                    num_multi_bits: NUM_MULTI_BITS,
                    plaintext_match_keys: true,
                },
                security,
            )
            .await;
        }
    }

    /// Test for the "wrapping-add" attack (issue #520).
    #[test]
    fn random_wrapping_add_attack() {
        const PER_USER_CAP: u32 = 15;
        const MAX_BREAKDOWN_KEY: u32 = 8;
        const NUM_MULTI_BITS: u32 = 3;
        const RECORD_COUNT: usize = 8;

        run(|| async {
            let mut rng = thread_rng();
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
            let trigger_values: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    ipa::<_, _, _, Fp31, MatchKey, BreakdownKey>(
                        ctx,
                        &input_rows,
                        IpaQueryConfig::no_window(PER_USER_CAP, MAX_BREAKDOWN_KEY, NUM_MULTI_BITS),
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();

            assert_eq!(MAX_BREAKDOWN_KEY as usize, trigger_values.len());
            println!("actual results: {trigger_values:#?}");

            // Check that the contribution never exceeds the cap.

            assert!(trigger_values
                .iter()
                .all(|v| v.as_u128() <= u128::from(PER_USER_CAP)));
            // Check that the sum of all contributions = cap.
            // The setup ensures that trigger values are always more than the per user cap.
            assert_eq!(
                u128::from(PER_USER_CAP),
                trigger_values
                    .into_iter()
                    .fold(0, |acc, x| acc + x.as_u128())
            );
        });
    }

    #[cfg(all(test, unit_test))]
    mod serialization {
        use generic_array::GenericArray;
        use proptest::{
            proptest,
            test_runner::{RngAlgorithm, TestRng},
        };
        use rand::distributions::{Distribution, Standard};
        use typenum::Unsigned;

        use crate::{
            ff::{Field, Fp31, PrimeField, Serializable},
            ipa_test_input,
            protocol::{
                ipa::{tests::Fp32BitPrime, IPAInputRow},
                BreakdownKey, MatchKey,
            },
            secret_sharing::{replicated::semi_honest::AdditiveShare, IntoShares},
            test_fixture::input::GenericReportTestInput,
        };

        fn serde_internal<F>(
            timestamp: u128,
            match_key: u64,
            trigger_bit: u128,
            breakdown_key: u128,
            trigger_value: u128,
            seed: u128,
        ) where
            F: Field + PrimeField + IntoShares<AdditiveShare<F>>,
            AdditiveShare<F>: Serializable,
            Standard: Distribution<F>,
            IPAInputRow<F, MatchKey, BreakdownKey>: Serializable,
        {
            // xorshift requires 16 byte seed and that's why it is picked here
            let mut rng = TestRng::from_seed(RngAlgorithm::XorShift, &seed.to_le_bytes());
            let reports: Vec<GenericReportTestInput<F, MatchKey, BreakdownKey>> = ipa_test_input!(
                [
                    { timestamp: timestamp, match_key: match_key, is_trigger_report: trigger_bit, breakdown_key: breakdown_key, trigger_value: trigger_value },
                ];
                (F, MatchKey, BreakdownKey)
            );
            let [a, b, ..]: [IPAInputRow<F, MatchKey, BreakdownKey>; 3] =
                reports[0].share_with(&mut rng);

            let mut buf = vec![
                    0u8;
                    2 * <IPAInputRow<F, MatchKey, BreakdownKey> as Serializable>::Size::USIZE
                ];
            a.serialize(GenericArray::from_mut_slice(
                &mut buf[..<IPAInputRow<F, MatchKey, BreakdownKey> as Serializable>::Size::USIZE],
            ));
            b.serialize(GenericArray::from_mut_slice(
                &mut buf[<IPAInputRow<F, MatchKey, BreakdownKey> as Serializable>::Size::USIZE..],
            ));

            assert_eq!(
                vec![a, b],
                IPAInputRow::<F, MatchKey, BreakdownKey>::from_byte_slice(&buf).collect::<Vec<_>>()
            );
        }

        proptest! {
            #[test]
            #[allow(clippy::ignored_unit_patterns)] // https://github.com/proptest-rs/proptest/issues/371
            fn serde(timestamp in 0..u128::MAX, match_key in 0..u64::MAX, trigger_bit in 0..u128::MAX, breakdown_key in 0..u128::MAX, trigger_value in 0..u128::MAX, seed in 0..u128::MAX) {
                serde_internal::<Fp31>(timestamp, match_key, trigger_bit, breakdown_key, trigger_value, seed);
                serde_internal::<Fp32BitPrime>(timestamp, match_key, trigger_bit, breakdown_key, trigger_value, seed);
            }
        }
    }

    /// Ensures that our communication and PRSS numbers don't go above the baseline.
    /// Prints a warning if they are currently below, so someone needs to adjust the baseline
    /// inside this test.
    ///
    /// It is possible to increase the number too if there is a good reason for it. This is a
    /// "catch all" type of test to make sure we don't miss an accidental regression.
    #[cfg(all(test, unit_test))]
    mod baselines {
        use super::*;
        use crate::{
            telemetry::{
                metrics::{
                    BYTES_SENT, INDEXED_PRSS_GENERATED, RECORDS_SENT, SEQUENTIAL_PRSS_GENERATED,
                },
                stats::Metrics,
            },
            test_fixture::ipa::IpaSecurityModel::{Malicious, SemiHonest},
        };

        const MAX_BREAKDOWN_KEY: u32 = 3;
        const ATTRIBUTION_WINDOW_SECONDS: u32 = 600;
        const NUM_MULTI_BITS: u32 = 3;

        fn cap_one() -> IpaQueryConfig {
            IpaQueryConfig::new(
                1,
                MAX_BREAKDOWN_KEY,
                ATTRIBUTION_WINDOW_SECONDS,
                NUM_MULTI_BITS,
            )
        }

        fn cap_three() -> IpaQueryConfig {
            IpaQueryConfig::new(
                3,
                MAX_BREAKDOWN_KEY,
                ATTRIBUTION_WINDOW_SECONDS,
                NUM_MULTI_BITS,
            )
        }

        fn generate_input<F: Field>(
        ) -> std::vec::IntoIter<GenericReportTestInput<F, MatchKey, BreakdownKey>> {
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
            ).into_iter()
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
            let test_config = TestWorldConfig::default().enable_metrics().with_seed(0);
            let world = TestWorld::new_with(test_config);
            let _: Vec<_> = match mode {
                Malicious => world.malicious(generate_input(), |ctx, input_rows| async move {
                    ipa::<_, _, _, Fp32BitPrime, MatchKey, BreakdownKey>(
                        ctx,
                        &input_rows,
                        query_config,
                    )
                    .await
                    .unwrap()
                }),
                SemiHonest => world.semi_honest(generate_input(), |ctx, input_rows| async move {
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
                    records_sent: 14_421,
                    bytes_sent: 47_100,
                    indexed_prss: 19_137,
                    seq_prss: 1118,
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
                    records_sent: 21_756,
                    bytes_sent: 76_440,
                    indexed_prss: 28_146,
                    seq_prss: 1118,
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
                    records_sent: 35_163,
                    bytes_sent: 130_068,
                    indexed_prss: 72_447,
                    seq_prss: 1132,
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
                    records_sent: 53_865,
                    bytes_sent: 204_876,
                    indexed_prss: 109_734,
                    seq_prss: 1132,
                },
            )
            .await;
        }
    }
}
