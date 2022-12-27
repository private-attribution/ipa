use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use async_trait::async_trait;
use futures::Stream;
use futures_util::StreamExt;
use rand::rngs::StdRng;
use rand::thread_rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use crate::ff::Field;
use crate::helpers::messaging::Gateway;
use crate::helpers::{negotiate_prss};
use crate::helpers::query::QueryInput;
use crate::protocol::basics::SecureMul;
use crate::protocol::context::SemiHonestContext;
use crate::protocol::{RecordId, Step};
use crate::secret_sharing::Replicated;

#[async_trait]
trait Protocol {
    type Output: Send;

    async fn run<S: Stream<Item = Vec<u8>> + Send + Unpin>(self, input: S) -> Self::Output;
}

struct TestMultiply<F, R> {
    rng: R,
    gateway: Gateway,
    _phantom: PhantomData<F>
}

impl <F, R> Debug for TestMultiply<F, R> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "test_multiply_protocol[role={:?}]", self.gateway.role())
    }
}

impl <F: Field> TestMultiply<F, StdRng> {
    pub fn new(gateway: Gateway) -> Self {
        Self {
            gateway,
            rng: StdRng::from_entropy(),
            _phantom: PhantomData::default(),
        }
    }
}

#[async_trait]
impl <F: Field, R: RngCore + CryptoRng + Send> Protocol for TestMultiply<F, R> {
    type Output = Vec<Replicated<F>>;

    async fn run<S: Stream<Item=Vec<u8>> + Send + Unpin>(mut self, mut input: S) -> Self::Output {
        let step = Step::default().narrow("test-multiply");
        let prss = negotiate_prss(&self.gateway, &step, &mut self.rng).await.unwrap();

        println!("prss is ready");
        let ctx = SemiHonestContext::<F>::new(&prss, &self.gateway);
        let mut results = Vec::new();
        while let Some(v) = input.next().await {
            // convert bytes to replicated shares
            let shares = v.chunks(2*F::SIZE_IN_BYTES as usize).map(|chunk| {
                let left = F::deserialize(&chunk[..=F::SIZE_IN_BYTES as usize]).unwrap();
                let right = F::deserialize(&chunk[F::SIZE_IN_BYTES as usize..]).unwrap();

                Replicated::new(left, right)
            });

            let mut a = None;
            let record_id = 0;
            for share in shares {
                match a {
                    None => a = Some(share),
                    Some(a_v) => {
                        let result = ctx.clone().multiply(RecordId::from(record_id), &a_v, &share).await.unwrap();
                        results.push(result);
                        a = None;
                    }
                }
            }

            assert!(a.is_none())
        }




        results
    }
}

// /// Executes a given query, including PRSS negotiation
// pub async fn execute<R: Protocol>(gateway: Gateway, protocol: R) -> R::Output {
//     todo!()
// }


#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use std::ops::Deref;
    use std::sync::Arc;
    use futures_util::future::join_all;
    use futures_util::stream;
    use futures_util::stream::FuturesUnordered;
    use crate::ff::Fp31;
    use crate::helpers::messaging::{Gateway, Message};
    use crate::helpers::{GatewayConfig, HelperIdentity, Role, RoleAssignment};
    use crate::helpers::network::Network;
    use crate::protocol::QueryId;
    use crate::query::executor::{Protocol, TestMultiply};
    use crate::secret_sharing::IntoShares;
    use crate::test_fixture::Reconstruct;
    use crate::test_fixture::transport::InMemoryNetwork;

    #[tokio::test]
    async fn e2e() {
        let network = InMemoryNetwork::default();
        let roles = RoleAssignment::new(HelperIdentity::make_three());
        let protocols: [_; 3] = join_all(network.transports.iter().enumerate().map(|(i, transport)| {
            let roles = roles.clone();
            async move {
                let network = Network::new(Arc::downgrade(transport), QueryId, roles);
                let gateway = Gateway::new(Role::all()[i], network, GatewayConfig::default()).await;

                TestMultiply::<Fp31, _>::new(gateway)
            }
        })).await.try_into().unwrap();

        let a = Fp31::from(4u128);
        let b = Fp31::from(3u128);

        let helper_shares = (a, b).share()
            .map(|v| {
                let mut slice = [0_u8; 4];
                v.0.left().serialize(&mut slice[..1]).unwrap();
                v.0.right().serialize(&mut slice[1..2]).unwrap();
                v.1.left().serialize(&mut slice[2..3]).unwrap();
                v.1.right().serialize(&mut slice[3..4]).unwrap();
                Box::new(stream::iter(std::iter::once(slice.to_vec())))
            });

        let results: [_; 3] = join_all(helper_shares.into_iter().zip(protocols).map(|(shares, protocol)| {
            protocol.run(shares)
        })).await.try_into().unwrap();

        let results = results.reconstruct();

        assert_eq!(1, results.len());
        assert_eq!(Fp31::from(12u128), results[0]);
    }
}