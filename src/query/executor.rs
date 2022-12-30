use crate::{
    ff::{Field, FieldType, Fp31},
    helpers::{
        messaging::Gateway,
        negotiate_prss,
        query::{QueryConfig, QueryType},
        transport::Error,
    },
    protocol::{context::SemiHonestContext, Step},
    secret_sharing::Replicated,
    task::JoinHandle,
};
use futures::Stream;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
#[cfg(all(feature = "shuttle", test))]
use shuttle::future as tokio;

pub trait Result: Send {
    fn into_bytes(self: Box<Self>) -> Vec<u8>;
}

impl<F: Field> Result for Vec<Replicated<F>> {
    fn into_bytes(self: Box<Self>) -> Vec<u8> {
        let mut r = vec![0u8; self.len() * Replicated::<F>::SIZE_IN_BYTES];
        for (i, share) in self.into_iter().enumerate() {
            share
                .serialize(&mut r[i * Replicated::<F>::SIZE_IN_BYTES..])
                .unwrap_or_else(|_| panic!("{share:?} fits into a 16 byte slice"));
        }

        r
    }
}

#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
async fn test_multiply<
    F: Field,
    St: Stream<Item = std::result::Result<Vec<u8>, Error>> + Send + Unpin,
>(
    ctx: SemiHonestContext<'_, F>,
    mut input: St,
) -> Vec<Replicated<F>> {
    use crate::protocol::basics::SecureMul;
    use crate::protocol::RecordId;
    use futures_util::StreamExt;

    let mut results = Vec::new();
    while let Some(v) = input.next().await {
        // multiply pairs
        let mut a = None;
        let mut record_id = 0_u32;
        for share in Replicated::<F>::from_byte_slice(&v.unwrap()) {
            match a {
                None => a = Some(share),
                Some(a_v) => {
                    let result = ctx
                        .clone()
                        .multiply(RecordId::from(record_id), &a_v, &share)
                        .await
                        .unwrap();
                    results.push(result);
                    record_id += 1;
                    a = None;
                }
            }
        }

        assert!(a.is_none());
    }

    results
}

#[allow(clippy::unused_async)]
async fn ipa<F: Field, St: Stream<Item = std::result::Result<Vec<u8>, Error>> + Send + Unpin>(
    _ctx: SemiHonestContext<'_, F>,
    _input: St,
) -> Vec<Replicated<F>> {
    todo!()
}

pub fn start_query<
    St: Stream<Item = std::result::Result<Vec<u8>, Error>> + Send + Unpin + 'static,
>(
    config: QueryConfig,
    gateway: Gateway,
    input: St,
) -> JoinHandle<Box<dyn Result>> {
    tokio::spawn(async move {
        // TODO: make it a generic argument for this function
        let mut rng = StdRng::from_entropy();
        // Negotiate PRSS first
        let step = Step::default().narrow(&config.query_type);
        let prss = negotiate_prss(&gateway, &step, &mut rng).await.unwrap();

        match config.field_type {
            FieldType::Fp2 => todo!(),
            FieldType::Fp31 => {
                let ctx = SemiHonestContext::<Fp31>::new(&prss, &gateway);
                match config.query_type {
                    #[cfg(any(test, feature = "cli", feature = "test-fixture"))]
                    QueryType::TestMultiply => {
                        Box::new(test_multiply(ctx, input).await) as Box<dyn Result>
                    }
                    QueryType::IPA => Box::new(ipa(ctx, input).await) as Box<dyn Result>,
                }
            }
            FieldType::Fp32BitPrime => {
                todo!()
            }
        }
    })
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use crate::secret_sharing::IntoShares;
    use crate::test_fixture::{Reconstruct, TestWorld};
    use futures_util::future::join_all;
    use futures_util::stream;

    #[tokio::test]
    async fn multiply() {
        let world = TestWorld::new().await;
        let contexts = world.contexts::<Fp31>();
        let a = [Fp31::from(4u128), Fp31::from(5u128)];
        let b = [Fp31::from(3u128), Fp31::from(6u128)];

        let helper_shares = (a, b).share().map(|(a, b)| {
            const SIZE: usize = Replicated::<Fp31>::SIZE_IN_BYTES;
            let r = a
                .into_iter()
                .zip(b)
                .flat_map(|(a, b)| {
                    let mut slice = [0_u8; 2 * SIZE];
                    a.serialize(&mut slice).unwrap();
                    b.serialize(&mut slice[SIZE..]).unwrap();

                    slice
                })
                .collect::<Vec<_>>();

            Box::new(stream::iter(std::iter::once(Ok(r))))
        });

        let results: [_; 3] = join_all(
            helper_shares
                .into_iter()
                .zip(contexts)
                .map(|(shares, context)| test_multiply(context, shares)),
        )
        .await
        .try_into()
        .unwrap();

        let results = results.reconstruct();

        assert_eq!(vec![Fp31::from(12u128), Fp31::from(30u128)], results);
    }

    #[test]
    fn serialize_result() {
        let [input, ..] = (0u128..=3).map(Fp31::from).collect::<Vec<_>>().share();
        let expected = input.clone();
        let bytes = Box::new(input).into_bytes();
        assert_eq!(
            expected,
            Replicated::<Fp31>::from_byte_slice(&bytes).collect::<Vec<_>>()
        );
    }
}
