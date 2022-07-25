use crate::field::Field;
use crate::prss::Participant;
use crate::replicated_secret_sharing::ReplicatedSecretSharing;
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tower_http::BoxError;

pub trait Message: Debug + Send + Serialize + DeserializeOwned + 'static {}

impl<T> Message for T where T: Debug + Send + Serialize + DeserializeOwned + 'static {}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DValue {
    index: u128,
    d: u128,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum HelperAddr {
    Left,
    Right,
}

#[async_trait]
pub trait Ring {
    async fn send<T: Message>(&self, dest: HelperAddr, msg: T) -> Result<(), BoxError>;
    async fn receive<T: Message>(&self, source: HelperAddr) -> Result<T, BoxError>;
}

#[derive(Debug)]
pub struct ProtocolContext<'a, R> {
    pub participant: Participant,
    pub helper_ring: &'a R,
}

#[derive(Debug)]
pub struct SecureMul<F> {
    index: u128,
    a_share: ReplicatedSecretSharing<F>,
    b_share: ReplicatedSecretSharing<F>,
}

impl<F: Field> SecureMul<F> {
    /// Executes the secure multiplication on the MPC helper side. Each helper will proceed with
    /// their part, eventually producing 2/3 shares of the product and that is what this function
    /// returns.
    ///
    /// ## Panics
    /// Well, we shouldn't panic given that the output is `Result`, so I pinky promise I'll fix that
    ///
    /// ## Errors
    /// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
    /// back via the error response
    pub async fn execute<R: Ring>(
        self,
        ctx: &ProtocolContext<'_, R>,
    ) -> Result<ReplicatedSecretSharing<F>, BoxError> {
        // generate shared randomness.
        let (s0, s1) = ctx.participant.generate_fields(self.index);

        // compute the value (d_i) we want to send to the right helper (i+1)
        let (a0, a1) = self.a_share.as_tuple();
        let (b0, b1) = self.b_share.as_tuple();
        let right_d: F = a0 * b1 + a1 * b0 - s0;

        // this ugliness is needed just to convert Field to u128. There are better ways to do it
        // and there is a PR open to make it easier
        let right_d: <F as Field>::Integer = right_d.into();
        let right_d: u128 = right_d.into();

        // notify helper on the right that we've computed our value
        ctx.helper_ring
            .send(
                HelperAddr::Right,
                DValue {
                    d: right_d,
                    index: self.index,
                },
            )
            .await?;

        // Sleep until helper on the left sends us their (d_i-1) value
        let DValue {
            d: left_d,
            index: left_index,
        } = ctx.helper_ring.receive(HelperAddr::Left).await?;

        // sanity check to make sure they've computed it using the same seed
        assert_eq!(left_index, self.index);

        // now we are ready to construct the result - 2/3 secret shares of a * b.
        let lhs = a0 * b0 + F::from(left_d) + s0;
        let rhs = a1 * b1 + s1;

        Ok(ReplicatedSecretSharing::new(lhs, rhs))
    }
}

#[cfg(test)]
mod tests {
    use std::any::TypeId;
    use std::collections::hash_map::Entry;
    use std::collections::HashMap;

    use async_trait::async_trait;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use crate::field::{Field, Fp31};
    use rand::rngs::mock::StepRng;
    use rand::Rng;
    use rand_core::RngCore;

    use crate::replicated_secret_sharing::ReplicatedSecretSharing;
    use crate::securemul::{HelperAddr, ProtocolContext, Ring, SecureMul};
    use axum::BoxError;
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use std::sync::Mutex;
    use tokio::sync::mpsc;

    type MessageBuf = HashMap<(HelperAddr, TypeId), Box<[u8]>>;

    #[derive(Debug)]
    struct MessageEnvelope {
        source: HelperAddr,
        type_id: TypeId,
        payload: Box<[u8]>,
    }

    #[derive(Debug)]
    struct TestRing {
        input_sender: mpsc::Sender<MessageEnvelope>,
        left: Option<mpsc::Sender<MessageEnvelope>>,
        right: Option<mpsc::Sender<MessageEnvelope>>,
        buf: Arc<Mutex<MessageBuf>>,
    }

    impl TestRing {
        pub fn new() -> Self {
            let (tx, mut rx) = mpsc::channel::<MessageEnvelope>(10);
            let buf = Arc::new(Mutex::new(HashMap::new()));

            tokio::spawn({
                let buf = Arc::clone(&buf);
                async move {
                    while let Some(item) = rx.recv().await {
                        let buf = &mut *buf.lock().unwrap();
                        match buf.entry((item.source, item.type_id)) {
                            Entry::Occupied(_entry) => {
                                panic!("Message {item:?} spot has been taken already")
                            }
                            Entry::Vacant(entry) => entry.insert(item.payload),
                        };
                    }
                }
            });

            Self {
                input_sender: tx,
                left: None,
                right: None,
                buf,
            }
        }

        pub fn set_left(&mut self, left: mpsc::Sender<MessageEnvelope>) {
            self.left = Some(left);
        }

        pub fn set_right(&mut self, right: mpsc::Sender<MessageEnvelope>) {
            self.right = Some(right);
        }
    }

    #[async_trait]
    impl Ring for TestRing {
        async fn send<T: Serialize + Send + 'static>(
            &self,
            dest: HelperAddr,
            msg: T,
        ) -> Result<(), BoxError> {
            assert!(self.left.is_some());
            assert!(self.right.is_some());

            let (target, source) = match dest {
                HelperAddr::Left => (self.left.as_ref().unwrap(), HelperAddr::Right),
                HelperAddr::Right => (self.right.as_ref().unwrap(), HelperAddr::Left),
            };

            let bytes = serde_json::to_vec(&msg).unwrap().into_boxed_slice();
            let envelope = MessageEnvelope {
                type_id: TypeId::of::<T>(),
                source,
                payload: bytes,
            };

            target.send(envelope).await.expect("boom");
            Ok(())
        }

        async fn receive<T: Send + DeserializeOwned + 'static>(
            &self,
            source: HelperAddr,
        ) -> Result<T, BoxError> {
            let buf = Arc::clone(&self.buf);

            tokio::spawn(async move {
                loop {
                    {
                        let buf = &mut *buf.lock().unwrap();
                        let key = (source, TypeId::of::<T>());
                        if let Entry::Occupied(entry) = buf.entry(key) {
                            let payload = entry.remove();
                            return serde_json::from_slice(&payload).unwrap();
                        }
                    }

                    tokio::task::yield_now().await;
                }
            })
            .await
            .map_err(|e| Box::new(e) as _)
        }
    }

    #[tokio::test]
    async fn basic() -> Result<(), BoxError> {
        let ring = make_helper_ring();
        let context = make_context(&ring);
        let mut rand = StepRng::new(1, 1);

        // TODO overflow seems to be broken
        assert_eq!(30, multiply_sync(&context, 6, 5, &mut rand).await?);
        assert_eq!(25, multiply_sync(&context, 5, 5, &mut rand).await?);
        assert_eq!(7, multiply_sync(&context, 7, 1, &mut rand).await?);
        assert_eq!(0, multiply_sync(&context, 0, 14, &mut rand).await?);

        Ok(())
    }

    async fn multiply_sync<R: RngCore>(
        context: &[ProtocolContext<'_, TestRing>; 3],
        a: u8,
        b: u8,
        rng: &mut R,
    ) -> Result<u8, BoxError> {
        assert!(a < Fp31::PRIME);
        assert!(b < Fp31::PRIME);

        let a = Fp31::from(u128::from(a));
        let b = Fp31::from(u128::from(b));

        thread_local! {
            static INDEX: AtomicU64 = AtomicU64::default();
        }

        let index = u128::from(INDEX.with(|i| i.fetch_add(1, Ordering::Release)));

        let a = share(a, rng);
        let b = share(b, rng);

        let result_shares = tokio::try_join!(
            SecureMul {
                a_share: a[0],
                b_share: b[0],
                index
            }
            .execute(&context[0]),
            SecureMul {
                a_share: a[1],
                b_share: b[1],
                index
            }
            .execute(&context[1]),
            SecureMul {
                a_share: a[2],
                b_share: b[2],
                index
            }
            .execute(&context[2]),
        )?;

        Ok(reconstruct(result_shares).into())
    }

    fn make_context(ring: &[TestRing; 3]) -> [ProtocolContext<TestRing>; 3] {
        let participants = crate::prss::test::make_three();

        ring.iter()
            .zip([participants.0, participants.1, participants.2])
            .map(|(helper_ring, participant)| ProtocolContext {
                participant,
                helper_ring,
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    fn make_helper_ring() -> [TestRing; 3] {
        let mut helpers = [TestRing::new(), TestRing::new(), TestRing::new()];

        helpers[0].set_left(helpers[2].input_sender.clone());
        helpers[1].set_left(helpers[0].input_sender.clone());
        helpers[2].set_left(helpers[1].input_sender.clone());

        helpers[0].set_right(helpers[1].input_sender.clone());
        helpers[1].set_right(helpers[2].input_sender.clone());
        helpers[2].set_right(helpers[0].input_sender.clone());

        helpers
    }

    fn share<R: RngCore>(a: Fp31, rng: &mut R) -> [ReplicatedSecretSharing<Fp31>; 3] {
        let x1 = Fp31::from(rng.gen_range(0..Fp31::PRIME));
        let x2 = Fp31::from(rng.gen_range(0..Fp31::PRIME));
        let x3 = a - (x1 + x2);

        [
            ReplicatedSecretSharing::new(x1, x2),
            ReplicatedSecretSharing::new(x2, x3),
            ReplicatedSecretSharing::new(x3, x1),
        ]
    }

    fn reconstruct<T: Field>(
        input: (
            ReplicatedSecretSharing<T>,
            ReplicatedSecretSharing<T>,
            ReplicatedSecretSharing<T>,
        ),
    ) -> T {
        input.0.as_tuple().0 + input.1.as_tuple().0 + input.2.as_tuple().0
    }
}
