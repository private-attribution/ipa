use std::{marker::PhantomData, sync::Arc};

use futures::{future, stream::iter, StreamExt, TryStreamExt};

use crate::{
    error::Error,
    ff::boolean_array::{BA20, BA3, BA8},
    helpers::{
        query::{HybridQueryParams, QuerySize},
        BodyStream, LengthDelimitedStream,
    },
    hpke::PrivateKeyRegistry,
    protocol::{context::UpgradableContext, ipa_prf::shuffle::Shuffle, step::ProtocolStep::Hybrid},
    report::hybrid::{EncryptedHybridReport, UniqueBytesValidator},
    secret_sharing::{replicated::semi_honest::AdditiveShare as ReplicatedShare, SharedValue},
};

pub type BreakdownKey = BA8;
pub type Value = BA3;
// TODO: remove this when encryption/decryption works for HybridReports
pub type Timestamp = BA20;

pub struct Query<C, HV, R: PrivateKeyRegistry> {
    config: HybridQueryParams,
    key_registry: Arc<R>,
    phantom_data: PhantomData<(C, HV)>,
}

impl<C, HV: SharedValue, R: PrivateKeyRegistry> Query<C, HV, R>
where
    C: UpgradableContext + Shuffle,
{
    pub fn new(query_params: HybridQueryParams, key_registry: Arc<R>) -> Self {
        Self {
            config: query_params,
            key_registry,
            phantom_data: PhantomData,
        }
    }

    #[tracing::instrument("hybrid_query", skip_all, fields(sz=%query_size))]
    pub async fn execute(
        self,
        ctx: C,
        query_size: QuerySize,
        input_stream: BodyStream,
    ) -> Result<Vec<ReplicatedShare<HV>>, Error> {
        let Self {
            config,
            key_registry,
            phantom_data: _,
        } = self;
        tracing::info!("New hybrid query: {config:?}");
        let _ctx = ctx.narrow(&Hybrid);
        let sz = usize::from(query_size);

        let mut unique_encrypted_hybrid_reports = UniqueBytesValidator::new(sz);

        if config.plaintext_match_keys {
            return Err(Error::Unsupported(
                "Hybrid queries do not currently support plaintext match keys".to_string(),
            ));
        }

        let _input = LengthDelimitedStream::<EncryptedHybridReport, _>::new(input_stream)
            .map_err(Into::<Error>::into)
            .and_then(|enc_reports| {
                future::ready(
                    unique_encrypted_hybrid_reports
                        .check_duplicates(&enc_reports)
                        .map(|()| enc_reports)
                        .map_err(Into::<Error>::into),
                )
            })
            .map_ok(|enc_reports| {
                iter(enc_reports.into_iter().map({
                    |enc_report| {
                        enc_report
                            .decrypt::<R, BreakdownKey, Value, Timestamp>(key_registry.as_ref())
                            .map_err(Into::<Error>::into)
                    }
                }))
            })
            .try_flatten()
            .take(sz)
            .try_collect::<Vec<_>>()
            .await?;

        unimplemented!("query::runnner::HybridQuery.execute is not fully implemented")
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
        query::runner::HybridQuery,
        report::{OprfReport, DEFAULT_KEY_ID},
        secret_sharing::IntoShares,
        test_fixture::{ipa::TestRawDataRecord, join3v, Reconstruct, TestWorld},
    };

    #[tokio::test]
    // placeholder until the protocol is complete. can be updated to make sure we
    // get to the unimplemented() call
    #[should_panic(
        expected = "not implemented: query::runnner::HybridQuery.execute is not fully implemented"
    )]
    async fn encrypted_hybrid_reports() {
        const EXPECTED: &[u128] = &[0, 8, 5];

        // TODO: When Encryption/Decryption exists for HybridReports
        // update these to use that, rather than generating OprfReports
        let records: Vec<TestRawDataRecord> = vec![
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
        ];

        let query_size = QuerySize::try_from(records.len()).unwrap();

        let mut rng = StdRng::seed_from_u64(42);
        let key_id = DEFAULT_KEY_ID;
        let key_registry = Arc::new(KeyRegistry::<KeyPair>::random(1, &mut rng));

        let mut buffers: [_; 3] = std::array::from_fn(|_| Vec::new());

        let shares: [Vec<OprfReport<BA8, BA3, BA20>>; 3] = records.into_iter().share();
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
        }))
        .await;

        assert_eq!(
            results.reconstruct()[0..3]
                .iter()
                .map(U128Conversions::as_u128)
                .collect::<Vec<u128>>(),
            EXPECTED
        );
    }

    // cannot test for Err directly because join3v calls unwrap. This should be sufficient.
    #[tokio::test]
    #[should_panic(expected = "DuplicateBytes(3)")]
    async fn duplicate_encrypted_hybrid_reports() {
        // TODO: When Encryption/Decryption exists for HybridReports
        // update these to use that, rather than generating OprfReports
        let records: Vec<TestRawDataRecord> = vec![
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
        ];

        // this is double, since we duplicate the data below
        let query_size = QuerySize::try_from(records.len() * 2).unwrap();

        let mut rng = StdRng::seed_from_u64(42);
        let key_id = DEFAULT_KEY_ID;
        let key_registry = Arc::new(KeyRegistry::<KeyPair>::random(1, &mut rng));

        let mut buffers: [_; 3] = std::array::from_fn(|_| Vec::new());

        let shares: [Vec<OprfReport<BA8, BA3, BA20>>; 3] = records.into_iter().share();
        for (buf, shares) in zip(&mut buffers, shares) {
            for share in shares {
                share
                    .delimited_encrypt_to(key_id, key_registry.as_ref(), &mut rng, buf)
                    .unwrap();
            }
        }

        // duplicate all the data
        for buffer in &mut buffers {
            let original = buffer.clone();
            buffer.extend(original);
        }

        let world = TestWorld::default();
        let contexts = world.contexts();
        #[allow(clippy::large_futures)]
        let _results = join3v(buffers.into_iter().zip(contexts).map(|(buffer, ctx)| {
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
        }))
        .await;
    }

    // cannot test for Err directly because join3v calls unwrap. This should be sufficient.
    #[tokio::test]
    #[should_panic(
        expected = "Unsupported(\"Hybrid queries do not currently support plaintext match keys\")"
    )]
    async fn unsupported_plaintext_match_keys_hybrid_query() {
        // TODO: When Encryption/Decryption exists for HybridReports
        // update these to use that, rather than generating OprfReports
        let records: Vec<TestRawDataRecord> = vec![
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
        ];

        let query_size = QuerySize::try_from(records.len()).unwrap();

        let mut rng = StdRng::seed_from_u64(42);
        let key_id = DEFAULT_KEY_ID;
        let key_registry = Arc::new(KeyRegistry::<KeyPair>::random(1, &mut rng));

        let mut buffers: [_; 3] = std::array::from_fn(|_| Vec::new());

        let shares: [Vec<OprfReport<BA8, BA3, BA20>>; 3] = records.into_iter().share();
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
        let _results = join3v(buffers.into_iter().zip(contexts).map(|(buffer, ctx)| {
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
        }))
        .await;
    }
}
