use std::{
    convert::{Infallible, Into},
    marker::PhantomData,
    ops::Add,
    sync::Arc,
};

use futures::{StreamExt, TryStreamExt};
use generic_array::ArrayLength;

use super::QueryResult;
use crate::{
    error::{Error, LengthError},
    ff::{
        boolean::Boolean,
        boolean_array::{BooleanArray, BA3, BA32, BA8},
        curve_points::RP25519,
        ec_prime_field::Fp25519,
        Serializable, U128Conversions,
    },
    helpers::{
        query::{DpMechanism, HybridQueryParams, QueryConfig, QuerySize},
        setup_cross_shard_prss,
        stream::TryFlattenItersExt,
        BodyStream, Gateway, LengthDelimitedStream,
    },
    hpke::PrivateKeyRegistry,
    protocol::{
        basics::{shard_fin::FinalizerContext, BooleanArrayMul, BooleanProtocols, Reveal},
        context::{
            DZKPUpgraded, MacUpgraded, ShardedContext, ShardedMaliciousContext, UpgradableContext,
        },
        hybrid::{
            hybrid_protocol,
            oprf::{CONV_CHUNK, PRF_CHUNK},
            step::HybridStep,
        },
        ipa_prf::{oprf_padding::PaddingParameters, prf_eval::PrfSharing, shuffle::ShardedShuffle},
        prss::{Endpoint, FromPrss},
        step::ProtocolStep::Hybrid,
        Gate,
    },
    query::runner::reshard_tag::reshard_aad,
    report::hybrid::{
        EncryptedHybridReport, IndistinguishableHybridReport, UniqueTag, UniqueTagValidator,
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed, TransposeFrom,
        Vectorizable,
    },
    seq_join::seq_join,
    sharding::{ShardConfiguration, Sharded},
};

#[allow(dead_code)]
pub struct Query<C, HV, R: PrivateKeyRegistry> {
    config: HybridQueryParams,
    key_registry: Arc<R>,
    phantom_data: PhantomData<(C, HV)>,
}

#[allow(dead_code)]
impl<C, HV, R: PrivateKeyRegistry> Query<C, HV, R> {
    pub fn new(query_params: HybridQueryParams, key_registry: Arc<R>) -> Self {
        Self {
            config: query_params,
            key_registry,
            phantom_data: PhantomData,
        }
    }
}

impl<C, HV, R> Query<C, HV, R>
where
    C: UpgradableContext
        + ShardedShuffle
        + ShardedContext
        + FinalizerContext<FinalizingContext = DZKPUpgraded<C>>,
    HV: BooleanArray + U128Conversions,
    <HV as Serializable>::Size: Add<<HV as Serializable>::Size, Output: ArrayLength>,
    R: PrivateKeyRegistry,
    Replicated<Boolean, CONV_CHUNK>: BooleanProtocols<DZKPUpgraded<C>, CONV_CHUNK>,
    Replicated<Fp25519, PRF_CHUNK>:
        PrfSharing<MacUpgraded<C, Fp25519>, PRF_CHUNK, Field = Fp25519> + FromPrss,
    Replicated<RP25519, PRF_CHUNK>:
        Reveal<MacUpgraded<C, Fp25519>, Output = <RP25519 as Vectorizable<PRF_CHUNK>>::Array>,
    Replicated<Boolean>: BooleanProtocols<DZKPUpgraded<C>>,
    Replicated<HV>: Serializable,
    Replicated<BA8>: BooleanArrayMul<DZKPUpgraded<C>>
        + Reveal<DZKPUpgraded<C>, Output = <BA8 as Vectorizable<1>>::Array>,
    BitDecomposed<Replicated<Boolean, 256>>:
        for<'bt> TransposeFrom<&'bt Vec<Replicated<HV>>, Error = LengthError>,
    BitDecomposed<Replicated<Boolean, 256>>:
        for<'bt> TransposeFrom<&'bt [Replicated<HV>; 256], Error = Infallible>,
    Vec<Replicated<HV>>:
        for<'bt> TransposeFrom<&'bt BitDecomposed<Replicated<Boolean, 256>>, Error = LengthError>,
    DZKPUpgraded<C>: ShardedContext,
{
    #[tracing::instrument("hybrid_query", skip_all, fields(sz=%query_size))]
    pub async fn execute(
        self,
        ctx: C,
        query_size: QuerySize,
        input_stream: BodyStream,
    ) -> Result<Vec<Replicated<HV>>, Error> {
        let Self {
            config,
            key_registry,
            phantom_data: _,
        } = &self;

        tracing::info!("New hybrid query: {config:?}");
        let ctx = ctx.narrow(&Hybrid);
        let sz = usize::from(query_size);

        if config.plaintext_match_keys {
            return Err(Error::Unsupported(
                "Hybrid queries do not currently support plaintext match keys".to_string(),
            ));
        }

        let stream = LengthDelimitedStream::<EncryptedHybridReport<BA8, BA3>, _>::new(input_stream)
            .map_err(Into::into)
            .try_flatten_iters()
            .map(|enc_report_res| async move {
                enc_report_res.and_then(|enc_report| {
                    let dec_report = enc_report
                        .decrypt(key_registry.as_ref())
                        .map_err(Into::<Error>::into);
                    let unique_tag = UniqueTag::from_unique_bytes(&enc_report);
                    dec_report.map(|dec_report1| (dec_report1, unique_tag))
                })
            })
            .take(sz);

        let (decrypted_reports, resharded_tags) = reshard_aad(
            ctx.narrow(&HybridStep::ReshardByTag),
            seq_join(ctx.active_work(), stream),
            |ctx, _, tag| tag.shard_picker(ctx.shard_count()),
        )
        .await?;

        let mut unique_encrypted_hybrid_reports = UniqueTagValidator::new(resharded_tags.len());
        unique_encrypted_hybrid_reports.check_duplicates(&resharded_tags)?;

        let indistinguishable_reports: Vec<IndistinguishableHybridReport<BA8, BA3>> =
            decrypted_reports.into_iter().map(Into::into).collect();

        let dp_params: DpMechanism = match config.with_dp {
            0 => DpMechanism::NoDp,
            _ => DpMechanism::DiscreteLaplace {
                epsilon: config.epsilon,
            },
        };

        #[cfg(feature = "relaxed-dp")]
        let padding_params = PaddingParameters::relaxed();
        #[cfg(not(feature = "relaxed-dp"))]
        let padding_params = PaddingParameters::default();

        hybrid_protocol::<_, BA8, BA3, HV, 3, 256>(
            ctx,
            indistinguishable_reports,
            dp_params,
            padding_params,
        )
        .await
    }
}

pub async fn execute_hybrid_protocol<'a, R: PrivateKeyRegistry>(
    prss: &'a Endpoint,
    gateway: &'a Gateway,
    input: BodyStream,
    ipa_config: HybridQueryParams,
    config: &QueryConfig,
    key_registry: Arc<R>,
) -> QueryResult {
    let gate = Gate::default();
    let cross_shard_prss =
        setup_cross_shard_prss(gateway, &gate, prss.indexed(&gate), gateway).await?;
    let sharded = Sharded {
        shard_id: gateway.shard_id(),
        shard_count: gateway.shard_count(),
        prss: Arc::new(cross_shard_prss),
    };

    let ctx = ShardedMaliciousContext::new_with_gate(prss, gateway, gate, sharded);

    Ok(Box::new(
        Query::<_, BA32, R>::new(ipa_config, key_registry)
            .execute(ctx, config.size, input)
            .await?,
    ))
}

#[cfg(all(test, unit_test, feature = "in-memory-infra"))]
mod tests {
    use std::{
        iter::{repeat, zip},
        sync::Arc,
    };

    use rand::rngs::StdRng;
    use rand_core::SeedableRng;

    use crate::{
        ff::{
            boolean_array::{BA3, BA32, BA8},
            U128Conversions,
        },
        helpers::{
            query::{HybridQueryParams, QuerySize},
            BodyStream,
        },
        hpke::{KeyPair, KeyRegistry},
        query::runner::hybrid::Query as HybridQuery,
        report::{hybrid::HybridReport, DEFAULT_KEY_ID},
        secret_sharing::IntoShares,
        test_executor::run,
        test_fixture::{
            flatten3v,
            hybrid::{build_hybrid_records_and_expectation, TestHybridRecord},
            Reconstruct, RoundRobinInputDistribution, TestWorld, TestWorldConfig, WithShards,
        },
    };

    struct BufferAndKeyRegistry {
        buffers: [Vec<Vec<u8>>; 3],
        key_registry: Arc<KeyRegistry<KeyPair>>,
        query_sizes: Vec<QuerySize>,
    }

    fn build_buffers_from_records(records: &[TestHybridRecord], s: usize) -> BufferAndKeyRegistry {
        let mut rng = StdRng::seed_from_u64(42);
        let key_id = DEFAULT_KEY_ID;
        let key_registry = Arc::new(KeyRegistry::<KeyPair>::random(1, &mut rng));

        let mut buffers: [_; 3] = std::array::from_fn(|_| vec![Vec::new(); s]);
        let shares: [Vec<HybridReport<BA8, BA3>>; 3] = records.iter().cloned().share();
        for (buf, shares) in zip(&mut buffers, shares) {
            for (i, share) in shares.into_iter().enumerate() {
                share
                    .delimited_encrypt_to(key_id, key_registry.as_ref(), &mut rng, &mut buf[i % s])
                    .unwrap();
            }
        }

        let total_query_size = records.len();
        let base_size = total_query_size / s;
        let remainder = total_query_size % s;
        let query_sizes: Vec<_> = (0..s)
            .map(|i| {
                if i < remainder {
                    base_size + 1
                } else {
                    base_size
                }
            })
            .map(|size| QuerySize::try_from(size).unwrap())
            .collect();

        BufferAndKeyRegistry {
            buffers,
            key_registry,
            query_sizes,
        }
    }

    #[test]
    fn encrypted_hybrid_reports_happy() {
        // While this test currently checks for an unimplemented panic it is
        // designed to test for a correct result for a complete implementation.
        run(|| async {
            const SHARDS: usize = 2;
            let (test_hybrid_records, mut expected) = build_hybrid_records_and_expectation();

            match expected.len() {
                len if len < 256 => {
                    expected.extend(repeat(0).take(256 - len));
                }
                len if len > 256 => {
                    panic!("no support for more than 256 breakdown_keys");
                }
                _ => {}
            }

            let BufferAndKeyRegistry {
                buffers,
                key_registry,
                query_sizes,
            } = build_buffers_from_records(&test_hybrid_records, SHARDS);

            let world = TestWorld::<WithShards<SHARDS>>::with_shards(TestWorldConfig::default());
            let contexts = world.malicious_contexts();

            #[allow(clippy::large_futures)]
            let results = flatten3v(buffers.into_iter().zip(contexts).map(
                |(helper_buffers, helper_ctxs)| {
                    helper_buffers
                        .into_iter()
                        .zip(helper_ctxs)
                        .zip(query_sizes.clone())
                        .map(|((buffer, ctx), query_size)| {
                            let query_params = HybridQueryParams {
                                with_dp: 0,
                                ..Default::default()
                            };
                            let input = BodyStream::from(buffer);

                            HybridQuery::<_, BA32, KeyRegistry<KeyPair>>::new(
                                query_params,
                                Arc::clone(&key_registry),
                            )
                            .execute(ctx, query_size, input)
                        })
                },
            ))
            .await;

            let leader_results: Vec<u32> = [
                results[0].as_ref().unwrap().clone(),
                results[1].as_ref().unwrap().clone(),
                results[2].as_ref().unwrap().clone(),
            ]
            .reconstruct()
            .iter()
            .map(U128Conversions::as_u128)
            .map(|x| u32::try_from(x).expect("test values constructed to fit in u32"))
            .collect::<Vec<u32>>();

            assert_eq!(expected, leader_results);

            let follower_results = [
                results[3].as_ref().unwrap().clone(),
                results[4].as_ref().unwrap().clone(),
                results[5].as_ref().unwrap().clone(),
            ]
            .reconstruct();
            assert_eq!(0, follower_results.len());
        });
    }

    // cannot test for Err directly because join3v calls unwrap. This should be sufficient.
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    #[should_panic(expected = "DuplicateBytes")]
    async fn duplicate_encrypted_hybrid_reports() {
        const SHARDS: usize = 2;
        let (test_hybrid_records, _expected) = build_hybrid_records_and_expectation();

        let BufferAndKeyRegistry {
            mut buffers,
            key_registry,
            query_sizes,
        } = build_buffers_from_records(&test_hybrid_records, SHARDS);

        // this is double, since we duplicate the data below
        let query_sizes = query_sizes
            .into_iter()
            .map(|query_size| QuerySize::try_from(usize::from(query_size) * 2).unwrap())
            .collect::<Vec<_>>();

        // duplicate all the data across shards

        for helper_buffers in &mut buffers {
            // Get the last shard buffer to use for the first shard buffer extension
            let last_shard_buffer = helper_buffers.last().unwrap().clone();
            let len = helper_buffers.len();
            for i in 0..len {
                if i > 0 {
                    let previous = &helper_buffers[i - 1].clone();
                    helper_buffers[i].extend_from_slice(previous);
                } else {
                    helper_buffers[i].extend_from_slice(&last_shard_buffer);
                }
            }
        }

        let world: TestWorld<WithShards<SHARDS, RoundRobinInputDistribution>> =
            TestWorld::with_shards(TestWorldConfig::default());
        let contexts = world.malicious_contexts();

        #[allow(clippy::large_futures)]
        let results = flatten3v(buffers.into_iter().zip(contexts).map(
            |(helper_buffers, helper_ctxs)| {
                helper_buffers
                    .into_iter()
                    .zip(helper_ctxs)
                    .zip(query_sizes.clone())
                    .map(|((buffer, ctx), query_size)| {
                        let query_params = HybridQueryParams::default();
                        let input = BodyStream::from(buffer);

                        HybridQuery::<_, BA32, KeyRegistry<KeyPair>>::new(
                            query_params,
                            Arc::clone(&key_registry),
                        )
                        .execute(ctx, query_size, input)
                    })
            },
        ))
        .await;

        results.into_iter().map(|r| r.unwrap()).for_each(drop);
    }

    // cannot test for Err directly because join3v calls unwrap. This should be sufficient.
    #[tokio::test]
    #[should_panic(
        expected = "Unsupported(\"Hybrid queries do not currently support plaintext match keys\")"
    )]
    async fn unsupported_plaintext_match_keys_hybrid_query() {
        const SHARDS: usize = 2;
        let (test_hybrid_records, _expected) = build_hybrid_records_and_expectation();

        let BufferAndKeyRegistry {
            buffers,
            key_registry,
            query_sizes,
        } = build_buffers_from_records(&test_hybrid_records, SHARDS);

        let world: TestWorld<WithShards<SHARDS, RoundRobinInputDistribution>> =
            TestWorld::with_shards(TestWorldConfig::default());
        let contexts = world.malicious_contexts();

        #[allow(clippy::large_futures)]
        let results = flatten3v(buffers.into_iter().zip(contexts).map(
            |(helper_buffers, helper_ctxs)| {
                helper_buffers
                    .into_iter()
                    .zip(helper_ctxs)
                    .zip(query_sizes.clone())
                    .map(|((buffer, ctx), query_size)| {
                        let query_params = HybridQueryParams {
                            plaintext_match_keys: true,
                            ..Default::default()
                        };
                        let input = BodyStream::from(buffer);

                        HybridQuery::<_, BA32, KeyRegistry<KeyPair>>::new(
                            query_params,
                            Arc::clone(&key_registry),
                        )
                        .execute(ctx, query_size, input)
                    })
            },
        ))
        .await;

        results.into_iter().map(|r| r.unwrap()).for_each(drop);
    }
}
