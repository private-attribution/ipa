use crate::error::BoxError;
use crate::field::Field;
use crate::helpers::ring::{HelperAddr, Ring};
use crate::prss::Participant;
use crate::replicated_secret_sharing::ReplicatedSecretSharing;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use thiserror::Error;

/// Secure multiplication protocol using replicated secret sharing over some field `F`.
/// * [paper](https://eprint.iacr.org/2018/387.pdf)
#[derive(Debug)]
pub struct SecureMul<F> {
    index: u128,
    a_share: ReplicatedSecretSharing<F>,
    b_share: ReplicatedSecretSharing<F>,
}

/// A message sent by each helper when they've multiplied their own shares
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DValue {
    index: u128,
    d: u128,
}

/// Context used by each helper to perform computation. Currently they need access to shared
/// randomness generator (PRSS) and communication trait to send messages to each other.
/// Eventually when we have more than one protocol, this should be lifted to its own module
#[derive(Debug)]
pub struct ProtocolContext<'a, R> {
    pub participant: &'a Participant,
    pub helper_ring: &'a R,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error(
        "Shares calculated by peer used different index {their_index} than expected {my_index}"
    )]
    IndexMismatch { my_index: u128, their_index: u128 },
}

impl<F: Field> SecureMul<F> {
    /// Executes the secure multiplication on the MPC helper side. Each helper will proceed with
    /// their part, eventually producing 2/3 shares of the product and that is what this function
    /// returns.
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
        if left_index == self.index {
            // now we are ready to construct the result - 2/3 secret shares of a * b.
            let lhs = a0 * b0 + F::from(left_d) + s0;
            let rhs = a1 * b1 + s1 + F::from(right_d);

            Ok(ReplicatedSecretSharing::new(lhs, rhs))
        } else {
            Err(Box::new(Error::IndexMismatch {
                my_index: self.index,
                their_index: left_index,
            }))
        }
    }
}

/// Module to support streaming interface for secure multiplication
pub mod stream {
    use crate::error::BoxError;
    use crate::field::Field;
    use crate::helpers::ring::Ring;
    use crate::replicated_secret_sharing::ReplicatedSecretSharing;
    use crate::securemul::{ProtocolContext, SecureMul};
    use futures::{ready, Stream};
    use pin_project::pin_project;
    use std::future::Future;
    use std::mem;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tracing::error;

    /// A variant of stream transform that combines semantic of `StreamExt::chunks` and `StreamExt::scan`.
    /// Consumes the input stream and keeps accumulating items in the internal buffer until it reaches
    /// `capacity` elements. Then the elements are moved to the `f` function that must produce a future
    /// resolvable to the same type as element type of the input stream.
    ///
    /// When elements are given to the `f` function, no other elements will be taken off the input stream
    /// until the future returned by it is resolved. It is important to note that the resulting item
    /// returned by this function is kept in the buffer, so next time stream is polled, only (`capacity`-1)
    /// elements will be polled off before calling `f` again.
    ///
    /// If input stream yields `None` while buf does not have at least `capacity` elements, `f` will
    /// be called on partial buf
    #[pin_project]
    pub struct ChunkScan<St: Stream, F, Fut> {
        /// Input stream
        #[pin]
        stream: St,

        /// how many elements to keep in the buffer before calling `f`
        capacity: usize,

        /// Buffer for items taken off the input stream
        buf: Vec<St::Item>,

        /// Transforms Vec<Item> -> Future<Output=Result<Item, Error>>
        f: F,

        /// future in progress
        #[pin]
        future: Option<Fut>,
    }

    impl<St, F, Fut> Stream for ChunkScan<St, F, Fut>
    where
        St: Stream,
        St::Item: Clone,
        F: FnMut(Vec<St::Item>) -> Fut,
        Fut: Future<Output = Result<St::Item, BoxError>>,
    {
        type Item = St::Item;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let mut this = self.as_mut().project();

            loop {
                // if future is set we poll it first before taking anything off the input stream
                if let Some(fut) = this.future.as_mut().as_pin_mut() {
                    let item = ready!(fut.poll(cx));
                    this.future.set(None);

                    if let Err(e) = item {
                        // TODO (alex): we should propagate errors back to caller
                        error!({ e }, "An error occurred computing next stream element");
                        return Poll::Ready(None);
                    }
                    let item = item.unwrap();
                    this.buf.push(item.clone());

                    return Poll::Ready(Some(item));
                } else if let Some(item) = ready!(this.stream.as_mut().poll_next(cx)) {
                    // otherwise we poll the input stream
                    this.buf.push(item);
                    if this.buf.len() == *this.capacity {
                        let items = mem::replace(this.buf, Vec::with_capacity(2));
                        this.future.set(Some((this.f)(items)));
                    }
                } else if !this.buf.is_empty() {
                    // Input stream is closed, but we still have some items to process
                    let items = mem::take(this.buf);
                    this.future.set(Some((this.f)(items)));
                } else {
                    return Poll::Ready(None);
                }
            }
        }
    }

    impl<St, F, Fut> ChunkScan<St, F, Fut>
    where
        St: Stream,
        F: FnMut(Vec<St::Item>) -> Fut,
        Fut: Future<Output = Result<St::Item, BoxError>>,
    {
        pub fn new(stream: St, capacity: usize, f: F) -> Self {
            Self {
                stream,
                capacity,
                buf: Vec::with_capacity(capacity),
                f,
                future: None,
            }
        }
    }

    /// Consumes the input stream of replicated secret shares and produces a new stream with elements
    /// being the product of items in the input stream. For example, if (a, b, c) are elements of the
    /// input stream, output will contain two elements: (a*b, a*b*c)
    ///
    /// ## Panics
    /// Panics if one of the internal invariants does not hold.
    pub fn secure_multiply<'a, F, R, S>(
        input_stream: S,
        ctx: &'a ProtocolContext<'a, R>,
        index: u128,
    ) -> impl Stream<Item = ReplicatedSecretSharing<F>> + 'a
    where
        S: Stream<Item = ReplicatedSecretSharing<F>> + 'a,
        F: Field + 'static,
        R: Ring,
    {
        let mut index = index;

        // TODO (alex): is there a way to deal with async without pinning stream to the heap?
        Box::pin(ChunkScan::new(
            input_stream,
            2, // buffer two elements
            move |mut items: Vec<ReplicatedSecretSharing<F>>| {
                debug_assert!(items.len() == 2);

                let b_share = items.pop().unwrap();
                let a_share = items.pop().unwrap();
                index += 1;

                let secure_mul = SecureMul {
                    index,
                    a_share,
                    b_share,
                };
                secure_mul.execute(ctx)
            },
        ))
    }
}

#[cfg(test)]
mod tests {

    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::field::{Field, Fp31};
    use rand::rngs::mock::StepRng;
    use rand::Rng;
    use rand_core::RngCore;

    use crate::replicated_secret_sharing::ReplicatedSecretSharing;

    use futures::{stream, StreamExt};
    use futures_util::future::join_all;

    use crate::prss::Participant;

    use crate::error::BoxError;
    use crate::helpers;
    use crate::helpers::ring::mock::TestHelper;
    use crate::securemul::stream::secure_multiply;
    use crate::securemul::{ProtocolContext, SecureMul};

    #[tokio::test]
    async fn basic() -> Result<(), BoxError> {
        let ring = helpers::ring::mock::make_three();
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

    /// Secure multiplication may be used with Stream API where shares are provided as elements
    /// of a `Stream`.
    #[tokio::test]
    async fn supports_stream_of_secret_shares() {
        // we compute a*b*c in this test. 4*3*2 = 24
        let mut rand = StepRng::new(1, 1);
        let a = share(Fp31::from(4_u128), &mut rand);
        let b = share(Fp31::from(3_u128), &mut rand);
        let c = share(Fp31::from(2_u128), &mut rand);
        let start_index = 1024_u128;

        // setup helpers
        let ring = helpers::ring::mock::make_three();
        let participants = crate::prss::test::make_three();
        let participants = [participants.0, participants.1, participants.2];

        // dedicated streams for each helper
        let input = [
            stream::iter(vec![a[0], b[0], c[0]]),
            stream::iter(vec![a[1], b[1], c[1]]),
            stream::iter(vec![a[2], b[2], c[2]]),
        ];

        // create 3 tasks (1 per helper) that will execute secure multiplication
        let handles = input.into_iter().zip(participants).zip(ring).map(
            |((input, participant), helper_ring)| {
                tokio::spawn(async move {
                    let ctx = ProtocolContext {
                        participant: &participant,
                        helper_ring: &helper_ring,
                    };
                    let mut stream = secure_multiply(input, &ctx, start_index);

                    // compute a*b
                    let _ = stream.next().await.expect("Failed to compute a*b");

                    // compute (a*b)*c and return it
                    stream.next().await.expect("Failed to compute a*b*c")
                })
            },
        );

        let result_shares: [ReplicatedSecretSharing<Fp31>; 3] =
            join_all(handles.map(|handle| async { handle.await.unwrap() }))
                .await
                .try_into()
                .unwrap();
        let result_shares = (result_shares[0], result_shares[1], result_shares[2]);

        assert_eq!(Fp31::from(24_u128), validate_and_reconstruct(result_shares));
    }

    async fn multiply_sync<R: RngCore>(
        context: &[ProtocolContext<'_, TestHelper>; 3],
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

    fn make_context<'a>(
        ring: &'a [TestHelper; 3],
        participants: &'a (Participant, Participant, Participant),
    ) -> [ProtocolContext<'a, TestHelper>; 3] {
        ring.iter()
            .zip([&participants.0, &participants.1, &participants.2])
            .map(|(helper_ring, participant)| ProtocolContext {
                participant,
                helper_ring,
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    /// Shares `input` into 3 replicated secret shares using the provided `rng` implementation
    fn share<R: RngCore>(input: Fp31, rng: &mut R) -> [ReplicatedSecretSharing<Fp31>; 3] {
        let x1 = Fp31::from(rng.gen_range(0..Fp31::PRIME));
        let x2 = Fp31::from(rng.gen_range(0..Fp31::PRIME));
        let x3 = input - (x1 + x2);

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
