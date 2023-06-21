use crate::{
    error::Error,
    ff::{Gf2, PrimeField, Serializable},
    helpers::{query::IpaQueryConfig, BodyStream, LengthDelimitedStream, RecordsStream},
    hpke::{KeyPair, KeyRegistry},
    protocol::{
        attribution::input::{MCAggregateCreditOutputRow, MCCappedCreditsWithAggregationBit},
        basics::{Reshare, ShareKnownValue},
        boolean::RandomBits,
        context::{UpgradableContext, UpgradedContext},
        ipa::{ipa, IPAInputRow},
        sort::generate_permutation::ShuffledPermutationWrapper,
        BasicProtocols, BreakdownKey, MatchKey, RecordId,
    },
    report::{EncryptedReport, EventType, InvalidReportError},
    secret_sharing::{
        replicated::{malicious::DowngradeMalicious, semi_honest::AdditiveShare},
        Linear as LinearSecretSharing,
    },
};
use futures::{
    stream::{iter, repeat},
    Stream, StreamExt, TryStreamExt,
};
use std::{marker::PhantomData, sync::Arc};

pub struct IpaQuery<F, C, S> {
    config: IpaQueryConfig,
    key_registry: Arc<KeyRegistry<KeyPair>>,
    phantom_data: PhantomData<(F, C, S)>,
}

impl<F, C, S> IpaQuery<F, C, S> {
    pub fn new(config: IpaQueryConfig, key_registry: Arc<KeyRegistry<KeyPair>>) -> Self {
        Self {
            config,
            key_registry,
            phantom_data: PhantomData,
        }
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
    AdditiveShare<F>: Serializable + ShareKnownValue<C, F>,
    IPAInputRow<F, MatchKey, BreakdownKey>: Serializable,
    ShuffledPermutationWrapper<S, C::UpgradedContext<F>>: DowngradeMalicious<Target = Vec<u32>>,
    MCCappedCreditsWithAggregationBit<F, S>:
        DowngradeMalicious<Target = MCCappedCreditsWithAggregationBit<F, AdditiveShare<F>>>,
    MCAggregateCreditOutputRow<F, S, BreakdownKey>:
        DowngradeMalicious<Target = MCAggregateCreditOutputRow<F, AdditiveShare<F>, BreakdownKey>>,
    AdditiveShare<F>: Serializable,
{
    #[tracing::instrument("ipa_query", skip_all)]
    pub async fn execute<'a>(
        self,
        ctx: C,
        input_stream: BodyStream,
    ) -> Result<Vec<MCAggregateCreditOutputRow<F, AdditiveShare<F>, BreakdownKey>>, Error> {
        let Self {
            config,
            key_registry,
            phantom_data: _,
        } = self;

        let input = if config.plaintext_match_keys {
            assert_stream_send(
                RecordsStream::<IPAInputRow<F, MatchKey, BreakdownKey>, _>::new(input_stream),
            )
            .try_concat()
            .await?
        } else {
            assert_stream_send(LengthDelimitedStream::<
                EncryptedReport<F, MatchKey, BreakdownKey, _>,
                _,
            >::new(input_stream))
            .map_err(Into::<Error>::into)
            .map_ok(|enc_reports| {
                iter(enc_reports.into_iter().map(|enc_report| {
                    enc_report
                        .decrypt(key_registry.as_ref())
                        .map_err(Into::<Error>::into)
                }))
            })
            .try_flatten()
            .zip(repeat(ctx.clone()))
            .map(|(res, ctx)| {
                res.and_then(|report| {
                    let timestamp = AdditiveShare::<F>::share_known_value(
                        &ctx,
                        F::try_from(report.timestamp.into())
                            .map_err(|_| InvalidReportError::Timestamp(report.timestamp))?,
                    );
                    let breakdown_key = AdditiveShare::<BreakdownKey>::share_known_value(
                        &ctx,
                        report.breakdown_key,
                    );
                    let is_trigger_bit = AdditiveShare::<F>::share_known_value(
                        &ctx,
                        match report.event_type {
                            EventType::Source => F::ZERO,
                            EventType::Trigger => F::ONE,
                        },
                    );

                    Ok(IPAInputRow {
                        timestamp,
                        mk_shares: report.mk_shares,
                        is_trigger_bit,
                        breakdown_key,
                        trigger_value: report.trigger_value,
                    })
                })
            })
            .try_collect::<Vec<_>>()
            .await?
        };

        ipa(ctx, input.as_slice(), config).await
    }
}

/// Helps to convince the compiler that things are `Send`. Like `seq_join::assert_send`, but for
/// streams.
///
/// <https://github.com/rust-lang/rust/issues/102211#issuecomment-1367900125>
pub fn assert_stream_send<'a, T>(
    st: impl Stream<Item = T> + Send + 'a,
) -> impl Stream<Item = T> + Send + 'a {
    st
}

/// no dependency on `weak-field` feature because it is enabled in tests by default
#[cfg(all(test, not(feature = "shuttle"), feature = "in-memory-infra",))]
mod tests {
    use std::iter::zip;

    use super::*;
    use crate::{
        ff::{Field, Fp31},
        ipa_test_input,
        report::{Report, DEFAULT_KEY_ID},
        secret_sharing::IntoShares,
        test_fixture::{input::GenericReportTestInput, join3v, Reconstruct, TestWorld},
    };
    use generic_array::GenericArray;
    use rand::rngs::StdRng;
    use rand_core::SeedableRng;
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
                plaintext_match_keys: true,
            };
            let input = BodyStream::from(shares);
            IpaQuery::new(query_config, Arc::new(KeyRegistry::empty())).execute(ctx, input)
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
                plaintext_match_keys: true,
            };
            IpaQuery::new(query_config, Arc::new(KeyRegistry::empty())).execute(ctx, shares.into())
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
    async fn encrypted_match_keys() {
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

        let mut rng = StdRng::seed_from_u64(42);
        let key_id = DEFAULT_KEY_ID;
        let key_registry = Arc::new(KeyRegistry::random(1, &mut rng));

        let mut buffers: [_; 3] = std::array::from_fn(|_| Vec::new());

        let shares: [Vec<Report<_, _, _>>; 3] = records.share();
        for (buf, shares) in zip(&mut buffers, shares) {
            for share in shares {
                share
                    .delimited_encrypt_to(key_id, key_registry.as_ref(), &mut rng, buf)
                    .unwrap();
            }
        }

        let world = TestWorld::default();
        let contexts = world.contexts();
        #[allow(clippy::large_futures)]
        let results = join3v(buffers.into_iter().zip(contexts).map(|(buffer, ctx)| {
            let query_config = IpaQueryConfig {
                num_multi_bits: 3,
                per_user_credit_cap: 3,
                attribution_window_seconds: None,
                max_breakdown_key: 3,
                plaintext_match_keys: false,
            };
            let input = BodyStream::from(buffer);
            IpaQuery::new(query_config, Arc::clone(&key_registry)).execute(ctx, input)
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
