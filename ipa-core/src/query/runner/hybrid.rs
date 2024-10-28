use std::{convert::Into, marker::PhantomData, sync::Arc};

use futures::{stream::iter, StreamExt, TryStreamExt};

use crate::{
    error::Error,
    ff::{
        boolean_array::{BooleanArray, BA20, BA3, BA8},
        U128Conversions,
    },
    helpers::{
        query::{DpMechanism, HybridQueryParams, QuerySize},
        BodyStream, LengthDelimitedStream,
    },
    hpke::PrivateKeyRegistry,
    protocol::{
        context::{ShardedContext, UpgradableContext},
        hybrid::{hybrid_protocol, step::HybridStep},
        ipa_prf::{oprf_padding::PaddingParameters, shuffle::Shuffle},
        step::ProtocolStep::Hybrid,
    },
    query::runner::reshard_tag::reshard_aad,
    report::hybrid::{
        EncryptedHybridReport, IndistinguishableHybridReport, UniqueTag, UniqueTagValidator,
    },
    secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
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
    C: UpgradableContext + Shuffle + ShardedContext,
    HV: BooleanArray + U128Conversions,
    R: PrivateKeyRegistry,
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
        } = self;

        tracing::info!("New hybrid query: {config:?}");
        let ctx = ctx.narrow(&Hybrid);
        let sz = usize::from(query_size);

        if config.plaintext_match_keys {
            return Err(Error::Unsupported(
                "Hybrid queries do not currently support plaintext match keys".to_string(),
            ));
        }

        let stream = LengthDelimitedStream::<EncryptedHybridReport, _>::new(input_stream)
            .map_err(Into::<Error>::into)
            .map_ok(|enc_reports| {
                iter(enc_reports.into_iter().map({
                    |enc_report| {
                        let dec_report = enc_report
                            .decrypt::<R, BA8, BA3, BA20>(key_registry.as_ref())
                            .map_err(Into::<Error>::into);
                        let unique_tag = UniqueTag::from_unique_bytes(&enc_report);
                        dec_report.map(|dec_report1| (dec_report1, unique_tag))
                    }
                }))
            })
            .try_flatten()
            .take(sz);
        let (decrypted_reports, resharded_tags) = reshard_aad(
            ctx.narrow(&HybridStep::ReshardByTag),
            stream,
            |ctx, _, tag| tag.shard_picker(ctx.shard_count()),
        )
        .await?;

        // this should use ? but until this returns a result,
        //we want to capture the panic for the test
        let mut unique_encrypted_hybrid_reports = UniqueTagValidator::new(resharded_tags.len());
        unique_encrypted_hybrid_reports
            .check_duplicates(&resharded_tags)
            .unwrap();

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

        match config.per_user_credit_cap {
            1 => hybrid_protocol::<_, BA8, BA3, HV, 1, 256>(ctx, indistinguishable_reports, dp_params, padding_params).await,
            2 | 4 => hybrid_protocol::<_, BA8, BA3, HV, 2, 256>(ctx, indistinguishable_reports, dp_params, padding_params).await,
            8 => hybrid_protocol::<_, BA8, BA3, HV, 3, 256>(ctx, indistinguishable_reports, dp_params, padding_params).await,
            16 => hybrid_protocol::<_, BA8, BA3, HV, 4, 256>(ctx, indistinguishable_reports, dp_params, padding_params).await,
            32 => hybrid_protocol::<_, BA8, BA3, HV, 5, 256>(ctx, indistinguishable_reports, dp_params, padding_params).await,
            64 => hybrid_protocol::<_, BA8, BA3, HV, 6, 256>(ctx, indistinguishable_reports, dp_params, padding_params).await,
            128 => hybrid_protocol::<_, BA8, BA3, HV, 7, 256>(ctx, indistinguishable_reports, dp_params, padding_params).await,
            _ => panic!(
                "Invalid value specified for per-user cap: {:?}. Must be one of 1, 2, 4, 8, 16, 32, 64, or 128.",
                config.per_user_credit_cap
            ),
        }
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::{iter::zip, sync::Arc};

    use rand::rngs::StdRng;
    use rand_core::SeedableRng;

    use crate::{
        ff::{
            boolean_array::{BA16, BA20, BA3, BA8},
            U128Conversions,
        },
        helpers::{
            query::{HybridQueryParams, QuerySize},
            BodyStream,
        },
        hpke::{KeyPair, KeyRegistry},
        query::runner::hybrid::Query as HybridQuery,
        report::{OprfReport, DEFAULT_KEY_ID},
        secret_sharing::{replicated::semi_honest::AdditiveShare, IntoShares},
        test_fixture::{
            flatten3v, ipa::TestRawDataRecord, Reconstruct, RoundRobinInputDistribution, TestWorld,
            TestWorldConfig, WithShards,
        },
    };

    const EXPECTED: &[u128] = &[0, 8, 5];

    fn build_records() -> Vec<TestRawDataRecord> {
        // TODO: When Encryption/Decryption exists for HybridReports
        // update these to use that, rather than generating OprfReports
        vec![
            TestRawDataRecord {
                timestamp: 0,
                user_id: 12345,
                is_trigger_report: false,
                breakdown_key: 2,
                trigger_value: 0,
            },
            TestRawDataRecord {
                timestamp: 4,
                user_id: 68362,
                is_trigger_report: false,
                breakdown_key: 1,
                trigger_value: 0,
            },
            TestRawDataRecord {
                timestamp: 10,
                user_id: 12345,
                is_trigger_report: true,
                breakdown_key: 0,
                trigger_value: 5,
            },
            TestRawDataRecord {
                timestamp: 12,
                user_id: 68362,
                is_trigger_report: true,
                breakdown_key: 0,
                trigger_value: 2,
            },
            TestRawDataRecord {
                timestamp: 20,
                user_id: 68362,
                is_trigger_report: false,
                breakdown_key: 1,
                trigger_value: 0,
            },
            TestRawDataRecord {
                timestamp: 30,
                user_id: 68362,
                is_trigger_report: true,
                breakdown_key: 1,
                trigger_value: 7,
            },
        ]
    }

    struct BufferAndKeyRegistry {
        buffers: [Vec<Vec<u8>>; 3],
        key_registry: Arc<KeyRegistry<KeyPair>>,
        query_sizes: Vec<QuerySize>,
    }

    fn build_buffers_from_records(records: &[TestRawDataRecord], s: usize) -> BufferAndKeyRegistry {
        let mut rng = StdRng::seed_from_u64(42);
        let key_id = DEFAULT_KEY_ID;
        let key_registry = Arc::new(KeyRegistry::<KeyPair>::random(1, &mut rng));

        let mut buffers: [_; 3] = std::array::from_fn(|_| vec![Vec::new(); s]);
        let shares: [Vec<OprfReport<BA8, BA3, BA20>>; 3] = records.iter().cloned().share();
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

    #[tokio::test]
    // placeholder until the protocol is complete. can be updated to make sure we
    // get to the unimplemented() call
    #[should_panic(
        expected = "not implemented: protocol::hybrid::hybrid_protocol is not fully implemented"
    )]
    async fn encrypted_hybrid_reports() {
        // While this test currently checks for an unimplemented panic it is
        // designed to test for a correct result for a complete implementation.

        const SHARDS: usize = 2;
        let records = build_records();

        let BufferAndKeyRegistry {
            buffers,
            key_registry,
            query_sizes,
        } = build_buffers_from_records(&records, SHARDS);

        let world: TestWorld<WithShards<SHARDS, RoundRobinInputDistribution>> =
            TestWorld::with_shards(TestWorldConfig::default());
        let contexts = world.contexts();

        #[allow(clippy::large_futures)]
        let results = flatten3v(buffers.into_iter().zip(contexts).map(
            |(helper_buffers, helper_ctxs)| {
                helper_buffers
                    .into_iter()
                    .zip(helper_ctxs)
                    .zip(query_sizes.clone())
                    .map(|((buffer, ctx), query_size)| {
                        let query_params = HybridQueryParams {
                            per_user_credit_cap: 8,
                            max_breakdown_key: 3,
                            with_dp: 0,
                            epsilon: 5.0,
                            plaintext_match_keys: false,
                        };
                        let input = BodyStream::from(buffer);

                        HybridQuery::<_, BA16, KeyRegistry<KeyPair>>::new(
                            query_params,
                            Arc::clone(&key_registry),
                        )
                        .execute(ctx, query_size, input)
                    })
            },
        ))
        .await;

        let results: Vec<[Vec<AdditiveShare<BA16>>; 3]> = results
            .chunks(3)
            .map(|chunk| {
                [
                    chunk[0].as_ref().unwrap().clone(),
                    chunk[1].as_ref().unwrap().clone(),
                    chunk[2].as_ref().unwrap().clone(),
                ]
            })
            .collect();

        assert_eq!(
            results.into_iter().next().unwrap().reconstruct()[0..3]
                .iter()
                .map(U128Conversions::as_u128)
                .collect::<Vec<u128>>(),
            EXPECTED
        );
    }

    // cannot test for Err directly because join3v calls unwrap. This should be sufficient.
    #[tokio::test]
    #[should_panic(expected = "DuplicateBytes")]
    async fn duplicate_encrypted_hybrid_reports() {
        const SHARDS: usize = 2;
        let records = build_records();

        let BufferAndKeyRegistry {
            mut buffers,
            key_registry,
            query_sizes,
        } = build_buffers_from_records(&records, SHARDS);

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
        let contexts = world.contexts();

        #[allow(clippy::large_futures)]
        let results = flatten3v(buffers.into_iter().zip(contexts).map(
            |(helper_buffers, helper_ctxs)| {
                helper_buffers
                    .into_iter()
                    .zip(helper_ctxs)
                    .zip(query_sizes.clone())
                    .map(|((buffer, ctx), query_size)| {
                        let query_params = HybridQueryParams {
                            per_user_credit_cap: 8,
                            max_breakdown_key: 3,
                            with_dp: 0,
                            epsilon: 5.0,
                            plaintext_match_keys: false,
                        };
                        let input = BodyStream::from(buffer);

                        HybridQuery::<_, BA16, KeyRegistry<KeyPair>>::new(
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
        let records = build_records();

        let BufferAndKeyRegistry {
            buffers,
            key_registry,
            query_sizes,
        } = build_buffers_from_records(&records, SHARDS);

        let world: TestWorld<WithShards<SHARDS, RoundRobinInputDistribution>> =
            TestWorld::with_shards(TestWorldConfig::default());
        let contexts = world.contexts();

        #[allow(clippy::large_futures)]
        let results = flatten3v(buffers.into_iter().zip(contexts).map(
            |(helper_buffers, helper_ctxs)| {
                helper_buffers
                    .into_iter()
                    .zip(helper_ctxs)
                    .zip(query_sizes.clone())
                    .map(|((buffer, ctx), query_size)| {
                        let query_params = HybridQueryParams {
                            per_user_credit_cap: 8,
                            max_breakdown_key: 3,
                            with_dp: 0,
                            epsilon: 5.0,
                            plaintext_match_keys: true,
                        };
                        let input = BodyStream::from(buffer);

                        HybridQuery::<_, BA16, KeyRegistry<KeyPair>>::new(
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
