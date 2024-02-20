use std::marker::PhantomData;

use futures::{stream::iter, StreamExt, TryStreamExt};
use futures_util::stream::repeat;

use crate::{
    error::Error,
    ff::{
        boolean::Boolean,
        boolean_array::{BA20, BA3, BA4, BA5, BA6, BA7, BA8},
        Field, PrimeField, Serializable,
    },
    helpers::{
        query::{IpaQueryConfig, QuerySize},
        BodyStream, LengthDelimitedStream, RecordsStream,
    },
    hpke::{KeyPair, KeyRegistry},
    protocol::{
        basics::ShareKnownValue,
        context::{UpgradableContext, UpgradedContext},
        ipa_prf::{oprf_ipa, OPRFIPAInputRow},
    },
    report::{EncryptedOprfReport, EventType},
    secret_sharing::{
        replicated::{malicious::ExtendableField, semi_honest::AdditiveShare as Replicated},
        SharedValue,
    },
    sync::Arc,
};

pub struct OprfIpaQuery<C, F> {
    config: IpaQueryConfig,
    key_registry: Arc<KeyRegistry<KeyPair>>,
    phantom_data: PhantomData<(C, F)>,
}

impl<C, F> OprfIpaQuery<C, F> {
    pub fn new(config: IpaQueryConfig, key_registry: Arc<KeyRegistry<KeyPair>>) -> Self {
        Self {
            config,
            key_registry,
            phantom_data: PhantomData,
        }
    }
}

#[allow(clippy::too_many_lines)]
impl<C, F> OprfIpaQuery<C, F>
where
    C: UpgradableContext,
    C::UpgradedContext<F>: UpgradedContext<F, Share = Replicated<F>>,
    C::UpgradedContext<Boolean>: UpgradedContext<Boolean, Share = Replicated<Boolean>>,
    F: PrimeField + ExtendableField,
    Replicated<F>: Serializable + ShareKnownValue<C, F>,
    Replicated<Boolean>: Serializable + ShareKnownValue<C, Boolean>,
{
    #[tracing::instrument("oprf_ipa_query", skip_all, fields(sz=%query_size))]
    pub async fn execute<'a>(
        self,
        ctx: C,
        query_size: QuerySize,
        input_stream: BodyStream,
    ) -> Result<Vec<Replicated<F>>, Error> {
        let Self {
            config,
            key_registry,
            phantom_data: _,
        } = self;
        tracing::info!("New query: {config:?}");
        let sz = usize::from(query_size);

        let input = if config.plaintext_match_keys {
            let mut v = RecordsStream::<OPRFIPAInputRow<BA8, BA3, BA20>, _>::new(input_stream)
                .try_concat()
                .await?;
            v.truncate(sz);
            v
        } else {
            LengthDelimitedStream::<EncryptedOprfReport<BA8, BA3, BA20, _>, _>::new(input_stream)
                .map_err(Into::<Error>::into)
                .map_ok(|enc_reports| {
                    iter(enc_reports.into_iter().map(|enc_report| {
                        enc_report
                            .decrypt(key_registry.as_ref())
                            .map_err(Into::<Error>::into)
                    }))
                })
                .try_flatten()
                .take(sz)
                .zip(repeat(ctx.clone()))
                .map(|(res, ctx)| {
                    res.map(|report| {
                        let is_trigger = Replicated::<Boolean>::share_known_value(
                            &ctx,
                            match report.event_type {
                                EventType::Source => Boolean::ZERO,
                                EventType::Trigger => Boolean::ONE,
                            },
                        );

                        OPRFIPAInputRow {
                            timestamp: report.timestamp,
                            match_key: report.match_key,
                            is_trigger,
                            breakdown_key: report.breakdown_key,
                            trigger_value: report.trigger_value,
                        }
                    })
                })
                .try_collect::<Vec<_>>()
                .await?
        };

        let aws = config.attribution_window_seconds;
        match config.per_user_credit_cap {
            8 => oprf_ipa::<C, BA8, BA3, BA20, BA3, F>(ctx, input, aws).await,
            16 => oprf_ipa::<C, BA8, BA3, BA20, BA4, F>(ctx, input, aws).await,
            32 => oprf_ipa::<C, BA8, BA3, BA20, BA5, F>(ctx, input, aws).await,
            64 => oprf_ipa::<C, BA8, BA3, BA20, BA6, F>(ctx, input, aws).await,
            128 => oprf_ipa::<C, BA8, BA3, BA20, BA7, F>(ctx, input, aws).await,
            _ => panic!(
                "Invalid value specified for per-user cap: {:?}. Must be one of 8, 16, 32, 64, or 128.",
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
            boolean_array::{BA20, BA3, BA8},
            Field, Fp31,
        },
        helpers::{
            query::{IpaQueryConfig, QuerySize},
            BodyStream,
        },
        hpke::KeyRegistry,
        query::runner::OprfIpaQuery,
        report::{OprfReport, DEFAULT_KEY_ID},
        secret_sharing::IntoShares,
        test_fixture::{ipa::TestRawDataRecord, join3v, Reconstruct, TestWorld},
    };

    #[tokio::test]
    async fn encrypted_reports() {
        const EXPECTED: &[u128] = &[0, 8, 5];

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
        let key_registry = Arc::new(KeyRegistry::random(1, &mut rng));

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
            let query_config = IpaQueryConfig {
                num_multi_bits: 3,
                per_user_credit_cap: 8,
                attribution_window_seconds: None,
                max_breakdown_key: 3,
                plaintext_match_keys: false,
            };
            let input = BodyStream::from(buffer);
            OprfIpaQuery::<_, Fp31>::new(query_config, Arc::clone(&key_registry))
                .execute(ctx, query_size, input)
        }))
        .await;

        assert_eq!(
            results.reconstruct()[0..3]
                .iter()
                .map(Field::as_u128)
                .collect::<Vec<u128>>(),
            EXPECTED
        );
    }
}
