use crate::{
    error::Error,
    ff::{FieldType, Fp32BitPrime, GaloisField, PrimeField, Serializable},
    helpers::{query::IpaQueryConfig, ByteArrStream},
    protocol::{
        attribution::input::MCAggregateCreditOutputRow,
        context::{MaliciousContext, SemiHonestContext},
        ipa::{ipa, IPAInputRow},
        BreakdownKey, MatchKey,
    },
    query::ProtocolResult,
    secret_sharing::replicated::{malicious, semi_honest::AdditiveShare},
};
use futures_util::StreamExt;
use std::future::Future;
use typenum::Unsigned;

pub struct Runner(pub IpaQueryConfig);

impl Runner {
    pub async fn run(
        &self,
        ctx: SemiHonestContext<'_>,
        field: FieldType,
        input: ByteArrStream,
    ) -> Box<dyn ProtocolResult> {
        match field {
            #[cfg(any(test, feature = "weak-field"))]
            FieldType::Fp31 => Box::new(
                self.run_internal::<crate::ff::Fp31, MatchKey, BreakdownKey>(ctx, input)
                    .await
                    .expect("IPA query failed"),
            ),
            FieldType::Fp32BitPrime => Box::new(
                self.run_internal::<Fp32BitPrime, MatchKey, BreakdownKey>(ctx, input)
                    .await
                    .expect("IPA query failed"),
            ),
        }
    }

    // This is intentionally made not async because it does not capture `self`.
    fn run_internal<'a, F: PrimeField, MK: GaloisField, BK: GaloisField>(
        &self,
        ctx: SemiHonestContext<'a>,
        input: ByteArrStream,
    ) -> impl Future<
        Output = std::result::Result<
            Vec<MCAggregateCreditOutputRow<F, AdditiveShare<F>, BK>>,
            Error,
        >,
    > + 'a
    where
        IPAInputRow<F, MK, BK>: Serializable,
        AdditiveShare<F>: Serializable,
    {
        let config = self.0;
        async move {
            let mut input = input.align(<IPAInputRow<F, MK, BK> as Serializable>::Size::USIZE);
            let mut input_vec = Vec::new();
            while let Some(data) = input.next().await {
                input_vec.extend(IPAInputRow::<F, MK, BK>::from_byte_slice(&data.unwrap()));
            }

            ipa(ctx, input_vec.as_slice(), config).await
        }
    }

    pub async fn malicious_run(
        &self,
        ctx: MaliciousContext<'_>,
        field: FieldType,
        input: ByteArrStream,
    ) -> Box<dyn ProtocolResult> {
        match field {
            #[cfg(any(test, feature = "weak-field"))]
            FieldType::Fp31 => Box::new(
                self.malicious_run_internal::<crate::ff::Fp31, MatchKey, BreakdownKey>(ctx, input)
                    .await
                    .expect("IPA query failed"),
            ),
            FieldType::Fp32BitPrime => Box::new(
                self.malicious_run_internal::<Fp32BitPrime, MatchKey, BreakdownKey>(ctx, input)
                    .await
                    .expect("IPA query failed"),
            ),
        }
    }

    // This is intentionally made not async because it does not capture `self`.
    fn malicious_run_internal<
        'a,
        F: PrimeField + crate::secret_sharing::replicated::malicious::ExtendableField,
        MK: GaloisField,
        BK: GaloisField,
    >(
        &self,
        ctx: MaliciousContext<'a>,
        input: ByteArrStream,
    ) -> impl Future<
        Output = std::result::Result<
            Vec<MCAggregateCreditOutputRow<F, AdditiveShare<F>, BK>>,
            Error,
        >,
    > + 'a
    where
        IPAInputRow<F, MK, BK>: Serializable,
        AdditiveShare<F>: Serializable,
        malicious::AdditiveShare<F>: Serializable,
    {
        let config = self.0;
        async move {
            let mut input = input.align(<IPAInputRow<F, MK, BK> as Serializable>::Size::USIZE);
            let mut input_vec = Vec::new();
            while let Some(data) = input.next().await {
                input_vec.extend(IPAInputRow::<F, MK, BK>::from_byte_slice(&data.unwrap()));
            }

            ipa(ctx, input_vec.as_slice(), config).await
        }
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
        let results = join3v(records.into_iter().zip(contexts).map(|(shares, ctx)| {
            let query_config = IpaQueryConfig {
                num_multi_bits: 3,
                per_user_credit_cap: 3,
                attribution_window_seconds: None,
                max_breakdown_key: 3,
            };
            let input = ByteArrStream::from(shares);
            Runner(query_config).run_internal::<Fp31, MatchKey, BreakdownKey>(ctx, input)
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
        let results = join3v(records.into_iter().zip(contexts).map(|(shares, ctx)| {
            let query_config = IpaQueryConfig {
                num_multi_bits: 3,
                per_user_credit_cap: 3,
                attribution_window_seconds: None,
                max_breakdown_key: 3,
            };
            let input = ByteArrStream::from(shares);
            Runner(query_config).malicious_run_internal::<Fp31, MatchKey, BreakdownKey>(ctx, input)
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
