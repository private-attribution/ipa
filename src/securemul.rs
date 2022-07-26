use std::collections::VecDeque;
use crate::field::Field;
use crate::prss::Participant;
use crate::replicated_secret_sharing::ReplicatedSecretSharing;
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::future::Future;
use std::mem;
use std::pin::Pin;
use std::task::{Context, Poll};
use digest::Output;
use futures::{poll, ready, Stream, StreamExt};
use futures_util::TryFutureExt;
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
    pub name: &'static str,
    pub participant: &'a Participant,
    pub helper_ring: &'a R,
}

#[derive(Debug)]
pub struct SecureMul<F> {
    index: u128,
    a_share: ReplicatedSecretSharing<F>,
    b_share: ReplicatedSecretSharing<F>,
}

impl<F: Field> SecureMul<F> {

    pub async fn execute_or_throw<R: Ring + Debug>(self, ctx: &ProtocolContext<'_, R>) -> ReplicatedSecretSharing<F> {
        self.execute(ctx).await.unwrap()
    }

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
        println!("{} secure mul started: {self:?}", ctx.name);

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
        let rhs = a1 * b1 + s1 + F::from(right_d);

        println!("{} secure mul done: ({:?}, {:?})", ctx.name, lhs, rhs);
        Ok(ReplicatedSecretSharing::new(lhs, rhs))
    }
}

use pin_project::pin_project;

#[pin_project]
pub struct BufMap<St: Stream, F, Fut> {
    #[pin]
    stream: St,
    buf: Vec<St::Item>,
    f: F,
    #[pin]
    future: Option<Fut>,
}


impl<St: Stream, F: FnMut(Vec<St::Item>) -> Fut, Fut: Future<Output=St::Item>> Stream for BufMap<St, F, Fut>
    where St::Item: Clone {
    type Item = St::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.as_mut().project();

        loop {
            if let Some(fut) = this.future.as_mut().as_pin_mut() {
                let item = ready!(fut.poll(cx));
                this.future.set(None);
                this.buf.push(item.clone());

                return Poll::Ready(Some(item));
            } else if let Some(item) = ready!(this.stream.as_mut().poll_next(cx)) {
                this.buf.push(item);
                if this.buf.len() == 2 {
                    let items = mem::replace(this.buf, Vec::with_capacity(2));
                    this.future.set(Some((this.f)(items)))
                }
            } else {
                return Poll::Ready(None);
            }
        }
    }
}

impl<St: Stream, F: FnMut(Vec<St::Item>) -> Fut, Fut: Future<Output=St::Item>> BufMap<St, F, Fut> {
    pub fn new(stream: St, f: F) -> Self {
        Self { stream, buf: Vec::with_capacity(2), f, future: None }
    }
}

struct MultiplyStep<'a, R> {
    index: u128,
    ctx: ProtocolContext<'a, R>,
}

impl<'a, R: Ring + Debug> MultiplyStep<'a, R> {
    pub fn apply<F: Field + 'static, S: Stream<Item = ReplicatedSecretSharing<F>> + 'a + Unpin>(&'a mut self, st: S)
        -> impl Stream<Item = ReplicatedSecretSharing<F>> + 'a + Unpin {
        let ctx: &'a ProtocolContext<R> = &self.ctx;

        // TODO is there a way to deal with async without pinning stream to the heap?
        Box::pin(BufMap::new(st, |mut items: Vec<ReplicatedSecretSharing<F>>| {
            debug_assert!(items.len() == 2);

            let b = items.pop().unwrap();
            let a = items.pop().unwrap();
            self.index += 1;

            let mut secure_mul = SecureMul { index: self.index, a_share: a, b_share: b };
            secure_mul.execute_or_throw(ctx)
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::any::TypeId;
    use std::collections::hash_map::Entry;
    use std::collections::HashMap;
    use std::fmt::Debug;

    use async_trait::async_trait;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use crate::field::{Field, Fp31};
    use rand::rngs::mock::StepRng;
    use rand::Rng;
    use rand_core::RngCore;

    use crate::replicated_secret_sharing::ReplicatedSecretSharing;
    use crate::securemul::{BufMap, HelperAddr, MultiplyStep, ProtocolContext, Ring, SecureMul};
    use axum::BoxError;
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use std::sync::Mutex;
    use std::thread;
    use futures::{stream, StreamExt};
    use rand::distributions::Uniform;
    use rand::prelude::StdRng;
    use redis::Commands;
    use tokio::sync::mpsc;
    use crate::prss::Participant;

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

        async fn receive<T: Debug + Send + DeserializeOwned + 'static>(
            &self,
            source: HelperAddr,
        ) -> Result<T, BoxError> {
            let buf = Arc::clone(&self.buf);

            let res = tokio::spawn(async move {
                loop {
                    {
                        let buf = &mut *buf.lock().unwrap();
                        let key = (source, TypeId::of::<T>());
                        if let Entry::Occupied(entry) = buf.entry(key) {
                            let payload = entry.remove();
                            let obj: T = serde_json::from_slice(&payload).unwrap();

                            return obj;
                        }
                    }

                    tokio::task::yield_now().await;
                }
            })
                .await
                .map_err(|e| Box::new(e) as _);
            res
        }
    }

    #[tokio::test]
    async fn basic() -> Result<(), BoxError> {
        let ring = make_helper_ring();
        let participants = crate::prss::test::make_three();
        let context = make_context(&ring, &participants);
        let mut rand = StepRng::new(1, 1);

        assert_eq!(30, multiply_sync(&context, 6, 5, &mut rand).await?);
        assert_eq!(25, multiply_sync(&context, 5, 5, &mut rand).await?);
        assert_eq!(7, multiply_sync(&context, 7, 1, &mut rand).await?);
        assert_eq!(0, multiply_sync(&context, 0, 14, &mut rand).await?);
        assert_eq!(8, multiply_sync(&context, 7, 10, &mut rand).await?);
        assert_eq!(4, multiply_sync(&context, 5, 7, &mut rand).await?);
        assert_eq!(1, multiply_sync(&context, 16, 2, &mut rand).await?);

        Ok(())
    }

    #[tokio::test]
    async fn works_with_stream() {
        // we compute a*b*c in this test. 4*3*2 = 24
        let mut rand = StepRng::new(1, 1);
        let start_index = 1024_u128;
        let a = share(Fp31::from(4_u128), &mut rand);
        let b = share(Fp31::from(3_u128), &mut rand);
        let c = share(Fp31::from(2_u128), &mut rand);
        println!("a share:{a:?}\nb share:{b:?}\nc share:{c:?}");
        let [ring_0, ring_1, ring_2] = make_helper_ring();
        let participants = crate::prss::test::make_three();

        let (input1, input2, input3) = (
            stream::iter(vec![a[0], b[0], c[0]]),
            stream::iter(vec![a[1], b[1], c[1]]),
            stream::iter(vec![a[2], b[2], c[2]]),
        );


        let handle1 = tokio::spawn(async move {
            let mut multiply_step = MultiplyStep { index: start_index, ctx: ProtocolContext {
                name: "helper 1",
                participant: &participants.0,
                helper_ring: &ring_0
            } };
            let mut stream = multiply_step.apply(input1);
            let _ = stream.next().await;

            stream.next().await.expect("Stream produces multiplication result")
        });
        let handle2 = tokio::spawn(async move {
            let mut multiply_step = MultiplyStep { index: start_index, ctx: ProtocolContext {
                name: "helper 2",
                participant: &participants.1,
                helper_ring: &ring_1
            } };
            let mut stream = multiply_step.apply(input2);
            let _ = stream.next().await;

            stream.next().await.expect("Stream produces multiplication result")
        });
        let handle3 = tokio::spawn(async move {
            let mut multiply_step = MultiplyStep { index: start_index, ctx: ProtocolContext {
                name: "helper 3",
                participant: &participants.2,
                helper_ring: &ring_2
            } };
            let mut stream = multiply_step.apply(input3);
            let _ = stream.next().await;

            stream.next().await.expect("Stream produces multiplication result")
        });

        let (share1, share2, share3) = (handle1.await.unwrap(), handle2.await.unwrap(), handle3.await.unwrap());
        assert_eq!(Fp31::from(24_u128), validate_and_reconstruct((share1, share2, share3)));

        //
        //
        // let handle1 = tokio::spawn(async move {
        //     let mut helper1_stream = SecureMulStep::new(input1, start_index, &participants.0, &ring_0);
        //     let a_b_share1 = helper1_stream.next().await;
        // });
        // let handle2 = tokio::spawn(async move {
        //     let mut helper2_stream = SecureMulStep::new(input2, start_index, &participants.1, &ring_1);
        //     let a_b_share1 = helper2_stream.next().await;
        // });
        // let handle3 = tokio::spawn(async move {
        //     let mut helper3_stream = SecureMulStep::new(input3, start_index, &participants.2, &ring_2);
        //     let a_b_share1 = helper3_stream.next().await;
        // });
        //
        // handle1.await.unwrap()
        //
        // // helper1_stream.next().await
        // // helper1_stream.next().await
        // // helper1_stream.next().await
        //
        //
        // // let input = stream::iter(vec![])
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

        Ok(validate_and_reconstruct(result_shares).into())
    }

    fn make_context<'a>(ring: &'a [TestRing; 3], participants: &'a (Participant, Participant, Participant)) -> [ProtocolContext<'a, TestRing>; 3] {
        ring.iter()
            .zip([&participants.0, &participants.1, &participants.2])
            .enumerate()
            .map(|(i, (helper_ring, participant))| ProtocolContext {
                name: Box::leak(format!("helper: {i}").into_boxed_str()),
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

    fn validate_and_reconstruct<T: Field>(
        input: (
            ReplicatedSecretSharing<T>,
            ReplicatedSecretSharing<T>,
            ReplicatedSecretSharing<T>,
        ),
    ) -> T {
        assert_eq!(
            input.0.as_tuple().0 + input.1.as_tuple().0 + input.2.as_tuple().0,
            input.0.as_tuple().1 + input.1.as_tuple().1 + input.2.as_tuple().1
        );

        input.0.as_tuple().0 + input.1.as_tuple().0 + input.2.as_tuple().0
    }
}
