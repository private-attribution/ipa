use crate::{
    error::Error,
    ff::{Gf2, PrimeField, Serializable},
    helpers::{query::IpaQueryConfig, ByteArrStream},
    protocol::{
        attribution::input::{MCAggregateCreditOutputRow, MCCappedCreditsWithAggregationBit},
        basics::Reshare,
        boolean::RandomBits,
        context::{UpgradableContext, UpgradedContext},
        ipa::{ipa, IPAInputRow},
        sort::generate_permutation::ShuffledPermutationWrapper,
        BasicProtocols, BreakdownKey, MatchKey, RecordId,
    },
    secret_sharing::{
        replicated::{malicious::DowngradeMalicious, semi_honest::AdditiveShare},
        Linear as LinearSecretSharing,
    },
};
use futures::StreamExt;
use std::marker::PhantomData;
use typenum::Unsigned;

pub struct IpaQuery<F, C, S>(IpaQueryConfig, PhantomData<(F, C, S)>)
where
    F: PrimeField,
    AdditiveShare<F>: Serializable,
    C: UpgradableContext,
    C::UpgradedContext<F>: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F> + Serializable,
    IPAInputRow<F, MatchKey, BreakdownKey>: Serializable;

impl<F, C, S> IpaQuery<F, C, S>
where
    F: PrimeField,
    AdditiveShare<F>: Serializable,
    C: UpgradableContext,
    C::UpgradedContext<F>: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F> + Serializable,
    IPAInputRow<F, MatchKey, BreakdownKey>: Serializable,
{
    pub fn new(config: IpaQueryConfig) -> Self {
        Self(config, PhantomData)
    }
}

impl<F, C, S, SB> IpaQuery<F, C, S>
where
    C: UpgradableContext + Send,
    C::UpgradedContext<F>: UpgradedContext<F, Share = S> + RandomBits<F, Share = S>,
    S: LinearSecretSharing<F>
        + BasicProtocols<C::UpgradedContext<F>, F>
        + Reshare<C::UpgradedContext<F>, RecordId>
        + Serializable
        + DowngradeMalicious<Target = AdditiveShare<F>>
        + 'static,
    C::UpgradedContext<Gf2>: UpgradedContext<Gf2, Share = SB>,
    SB: LinearSecretSharing<Gf2>
        + BasicProtocols<C::UpgradedContext<Gf2>, Gf2>
        + DowngradeMalicious<Target = AdditiveShare<Gf2>>
        + 'static,
    F: PrimeField,
    IPAInputRow<F, MatchKey, BreakdownKey>: Serializable,
    ShuffledPermutationWrapper<S, C::UpgradedContext<F>>: DowngradeMalicious<Target = Vec<u32>>,
    MCCappedCreditsWithAggregationBit<F, S>:
        DowngradeMalicious<Target = MCCappedCreditsWithAggregationBit<F, AdditiveShare<F>>>,
    MCAggregateCreditOutputRow<F, S, BreakdownKey>:
        DowngradeMalicious<Target = MCAggregateCreditOutputRow<F, AdditiveShare<F>, BreakdownKey>>,
    AdditiveShare<F>: Serializable,
{
    pub async fn execute<'a>(
        self,
        ctx: C,
        input: ByteArrStream,
    ) -> Result<Vec<MCAggregateCreditOutputRow<F, AdditiveShare<F>, BreakdownKey>>, Error> {
        let Self(config, _) = self;

        let mut input =
            input.align(<IPAInputRow<F, MatchKey, BreakdownKey> as Serializable>::Size::USIZE);
        let mut input_vec = Vec::new();
        while let Some(data) = input.next().await {
            input_vec.extend(IPAInputRow::<F, MatchKey, BreakdownKey>::from_byte_slice(
                &data.unwrap(),
            ));
        }

        ipa(ctx, input_vec.as_slice(), config).await
    }
}

/// no dependency on `weak-field` feature because it is enabled in tests by default
#[cfg(all(test, not(feature = "shuttle"), feature = "in-memory-infra",))]
mod tests {
    use super::*;
    use crate::{
        ff::{Field, Fp31},
        ipa_test_input,
        secret_sharing::IntoShares,
        test_fixture::{input::GenericReportTestInput, join3v, Reconstruct, TestWorld},
    };
    use generic_array::GenericArray;
    use typenum::Unsigned;

    #[tokio::test]
    async fn ipa() {
        const EXPECTED: &[[u128; 2]] = &[[0, 0], [1, 2], [2, 3]];

        let records: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> = ipa_test_input!(
            [
                { timestamp: 0, match_key: 12345, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { timestamp: 0, match_key: 12345, is_trigger_report: 0, breakdown_key: 2, trigger_value: 0 },
                { timestamp: 0, match_key: 68362, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { timestamp: 0, match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 5 },
                { timestamp: 0, match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 2 },
            ];
            (Fp31, MatchKey, BreakdownKey)
        );
        let records = records
            .share()
            // TODO: a trait would be useful here to convert IntoShares<T> to IntoShares<Vec<u8>>
            .map(|shares| {
                shares
                    .into_iter()
                    .flat_map(|share: IPAInputRow<Fp31, MatchKey, BreakdownKey>| {
                        let mut buf = [0u8; <IPAInputRow<
                            Fp31,
                            MatchKey,
                            BreakdownKey,
                        > as Serializable>::Size::USIZE];
                        share.serialize(GenericArray::from_mut_slice(&mut buf));

                        buf
                    })
                    .collect::<Vec<_>>()
            });

        let world = TestWorld::default();
        let contexts = world.contexts();
        #[allow(clippy::large_futures)]
        let results = join3v(records.into_iter().zip(contexts).map(|(shares, ctx)| {
            let query_config = IpaQueryConfig {
                num_multi_bits: 3,
                per_user_credit_cap: 3,
                attribution_window_seconds: None,
                max_breakdown_key: 3,
            };
            let input = ByteArrStream::from(shares);
            IpaQuery::new(query_config).execute(ctx, input)
        }))
        .await;

        let results: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> =
            results.reconstruct();
        for (i, expected) in EXPECTED.iter().enumerate() {
            assert_eq!(
                *expected,
                [
                    results[i].breakdown_key.as_u128(),
                    results[i].trigger_value.as_u128()
                ]
            );
        }
    }

    #[tokio::test]
    async fn malicious_ipa() {
        const EXPECTED: &[[u128; 2]] = &[[0, 0], [1, 2], [2, 3]];

        let records: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> = ipa_test_input!(
            [
                { timestamp: 0, match_key: 12345, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { timestamp: 0, match_key: 12345, is_trigger_report: 0, breakdown_key: 2, trigger_value: 0 },
                { timestamp: 0, match_key: 68362, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { timestamp: 0, match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 5 },
                { timestamp: 0, match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 2 },
            ];
            (Fp31, MatchKey, BreakdownKey)
        );
        let records = records
            .share()
            // TODO: a trait would be useful here to convert IntoShares<T> to IntoShares<Vec<u8>>
            .map(|shares| {
                shares
                    .into_iter()
                    .flat_map(|share: IPAInputRow<Fp31, MatchKey, BreakdownKey>| {
                        let mut buf = [0u8; <IPAInputRow<
                            Fp31,
                            MatchKey,
                            BreakdownKey,
                        > as Serializable>::Size::USIZE];
                        share.serialize(GenericArray::from_mut_slice(&mut buf));

                        buf
                    })
                    .collect::<Vec<_>>()
            });

        let world = TestWorld::default();
        let contexts = world.malicious_contexts();
        #[allow(clippy::large_futures)]
        let results = join3v(records.into_iter().zip(contexts).map(|(shares, ctx)| {
            let query_config = IpaQueryConfig {
                num_multi_bits: 3,
                per_user_credit_cap: 3,
                attribution_window_seconds: None,
                max_breakdown_key: 3,
            };
            let input = ByteArrStream::from(shares);
            IpaQuery::new(query_config).execute(ctx, input)
        }))
        .await;

        let results: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> =
            results.reconstruct();
        for (i, expected) in EXPECTED.iter().enumerate() {
            assert_eq!(
                *expected,
                [
                    results[i].breakdown_key.as_u128(),
                    results[i].trigger_value.as_u128()
                ]
            );
        }
    }
}
