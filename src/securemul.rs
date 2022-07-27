use crate::error::BoxError;
use crate::field::Field;
use crate::helpers::ring::{HelperAddr, Ring};
use crate::prss::Participant;
use crate::replicated_secret_sharing::ReplicatedSecretSharing;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use thiserror::Error;

/// IKHC multiplication protocol
/// for use with replicated secret sharing over some field F.
/// K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, and B. Pinkas. High-throughput secure AES computation. In WAHC@CCS 2018, pp. 13–24, 2018
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
            let rhs = a1 * b1 + F::from(right_d) + s1;

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

    use crate::field::Field;
    use crate::helpers::ring::Ring;
    use crate::replicated_secret_sharing::ReplicatedSecretSharing;
    use crate::securemul::{ProtocolContext, SecureMul};
    use futures::Stream;

    use crate::chunkscan::ChunkScan;

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
