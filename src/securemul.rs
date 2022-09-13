use crate::error::BoxError;
use crate::field::Field;
use crate::helpers::mesh::{Gateway, Mesh};
use crate::helpers::Direction;
use crate::protocol::{RecordId, Step};
use crate::prss::{Participant, PrssSpace, SpaceIndex};
use crate::replicated_secret_sharing::ReplicatedSecretSharing;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use thiserror::Error;

/// A message sent by each helper when they've multiplied their own shares
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DValue<F> {
    d: F,
}

/// Context used by each helper to perform computation. Currently they need access to shared
/// randomness generator (see `Participant`) and communication trait to send messages to each other.
/// Eventually when we have more than one protocol, this should be lifted to its own module
#[derive(Debug)]
pub struct ProtocolContext<'a, G, S: SpaceIndex> {
    participant: &'a Participant<S>,
    gateway: &'a G,
}

/// IKHC multiplication protocol
/// for use with replicated secret sharing over some field F.
/// K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, and B. Pinkas. High-throughput secure AES computation. In WAHC@CCS 2018, pp. 13–24, 2018
#[derive(Debug)]
pub struct SecureMul<'a, G, S> {
    prss: &'a PrssSpace,
    gateway: &'a G,
    step: S,
    record_id: RecordId,
}

impl<'a, G, S: Step> SecureMul<'a, G, S> {
    /// Executes the secure multiplication on the MPC helper side. Each helper will proceed with
    /// their part, eventually producing 2/3 shares of the product and that is what this function
    /// returns.
    ///
    /// ## Errors
    /// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
    /// back via the error response
    pub async fn execute<M, F>(
        self,
        a: ReplicatedSecretSharing<F>,
        b: ReplicatedSecretSharing<F>,
    ) -> Result<ReplicatedSecretSharing<F>, BoxError>
    where
        M: Mesh,
        G: Gateway<M, S>,
        F: Field,
    {
        let mut channel = self.gateway.get_channel(self.step);

        // generate shared randomness.
        let (s0, s1) = self.prss.generate_fields(self.record_id.into());

        // compute the value (d_i) we want to send to the right helper (i+1)
        let (a0, a1) = a.as_tuple();
        let (b0, b1) = b.as_tuple();
        let right_d = a0 * b1 + a1 * b0 - s0;

        // notify helper on the right that we've computed our value
        channel
            .send(
                channel.identity().peer(Direction::Right),
                self.record_id,
                DValue { d: right_d },
            )
            .await?;

        // Sleep until helper on the left sends us their (d_i-1) value
        let DValue { d: left_d } = channel
            .receive(channel.identity().peer(Direction::Left), self.record_id)
            .await?;

        // now we are ready to construct the result - 2/3 secret shares of a * b.
        let lhs = a0 * b0 + left_d + s0;
        let rhs = a1 * b1 + right_d + s1;

        Ok(ReplicatedSecretSharing::new(lhs, rhs))
    }
}

impl<'a, G, S: Step + SpaceIndex> ProtocolContext<'a, G, S> {
    pub fn new(participant: &'a Participant<S>, gateway: &'a G) -> Self {
        Self {
            participant,
            gateway,
        }
    }

    /// Request multiplication for a given record. This function is intentionally made async
    /// to allow backpressure if infrastructure layer cannot keep up with protocols demand.
    /// In this case, function returns only when multiplication for this record can actually
    /// be processed.
    async fn multiply(&'a self, record_id: RecordId, step: S) -> SecureMul<'a, G, S> {
        SecureMul {
            prss: &self.participant[step],
            gateway: self.gateway,
            step,
            record_id,
        }
    }
}

#[derive(Error, Debug)]
pub enum Error {}

/// Module to support streaming interface for secure multiplication
pub mod stream {
    use crate::field::Field;
    use crate::replicated_secret_sharing::ReplicatedSecretSharing;
    use crate::securemul::ProtocolContext;
    use futures::Stream;

    use crate::chunkscan::ChunkScan;
    use crate::helpers::mesh::{Gateway, Mesh};
    use crate::protocol::{RecordId, Step};
    use crate::prss::SpaceIndex;

    #[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
    pub struct StreamingStep(u128);

    impl Step for StreamingStep {}
    impl SpaceIndex for StreamingStep {
        const MAX: usize = 1;

        fn as_usize(&self) -> usize {
            0
        }
    }

    /// Consumes the input stream of replicated secret shares and produces a new stream with elements
    /// being the product of items in the input stream. For example, if (a, b, c) are elements of the
    /// input stream, output will contain two elements: (a*b, a*b*c)
    ///
    /// ## Panics
    /// Panics if one of the internal invariants does not hold.
    pub fn secure_multiply<'a, F, M, G, S>(
        input_stream: S,
        ctx: &'a ProtocolContext<'a, G, StreamingStep>,
        _index: u128,
    ) -> impl Stream<Item = ReplicatedSecretSharing<F>> + 'a
    where
        S: Stream<Item = ReplicatedSecretSharing<F>> + 'a,
        F: Field + 'static,
        M: Mesh + 'a,
        G: Gateway<M, StreamingStep>,
    {
        let record_id = RecordId::from(1);
        let mut stream_element_idx = 0;

        // TODO (alex): is there a way to deal with async without pinning stream to the heap?
        Box::pin(ChunkScan::new(
            input_stream,
            2, // buffer two elements
            move |mut items: Vec<ReplicatedSecretSharing<F>>| async move {
                debug_assert!(items.len() == 2);

                let b_share = items.pop().unwrap();
                let a_share = items.pop().unwrap();
                stream_element_idx += 1;

                let mul = ctx
                    .multiply(record_id, StreamingStep(stream_element_idx))
                    .await;
                mul.execute(a_share, b_share).await
            },
        ))
    }

    #[cfg(test)]
    mod tests {
        use crate::field::Fp31;
        use crate::helpers;
        use crate::protocol::QueryId;
        use crate::replicated_secret_sharing::ReplicatedSecretSharing;
        use crate::securemul::stream::secure_multiply;
        use crate::securemul::tests::{share, validate_and_reconstruct};
        use crate::securemul::ProtocolContext;
        use futures::StreamExt;
        use futures_util::future::join_all;
        use futures_util::stream;
        use rand::rngs::mock::StepRng;

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
            let world = helpers::mock::make_world(QueryId);
            let participants = crate::prss::test::make_three();
            let participants = [participants.0, participants.1, participants.2];

            // dedicated streams for each helper
            let input = [
                stream::iter(vec![a[0], b[0], c[0]]),
                stream::iter(vec![a[1], b[1], c[1]]),
                stream::iter(vec![a[2], b[2], c[2]]),
            ];

            // create 3 tasks (1 per helper) that will execute secure multiplication
            let handles = input.into_iter().zip(participants).zip(world.gateways).map(
                |((input, prss), gateway)| {
                    tokio::spawn(async move {
                        let ctx = ProtocolContext::new(&prss, &gateway);
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
    }
}

pub mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use crate::field::{Field, Fp31};
    use rand::rngs::mock::StepRng;
    use rand::Rng;
    use rand_core::RngCore;

    use crate::replicated_secret_sharing::ReplicatedSecretSharing;

    use futures_util::future::join_all;
    use tokio::try_join;

    use crate::prss::{Participant, SpaceIndex};

    use crate::error::BoxError;
    use crate::helpers;

    use crate::helpers::mock::{TestHelperGateway, TestWorld};
    use crate::protocol::{QueryId, RecordId, Step};
    use crate::securemul::ProtocolContext;

    #[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
    enum TestStep {
        Mul1(u8),
        Mul2,
    }

    impl Step for TestStep {}

    impl SpaceIndex for TestStep {
        const MAX: usize = 2;

        fn as_usize(&self) -> usize {
            match self {
                TestStep::Mul1(_) => 0,
                TestStep::Mul2 => 1,
            }
        }
    }

    #[tokio::test]
    async fn basic() -> Result<(), BoxError> {
        let world = helpers::mock::make_world(QueryId);
        let participants = crate::prss::test::make_three();
        let context = make_context(&world, &participants);
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

    /// This test ensures that many secure multiplications can run concurrently as long as
    /// they all have unique id associated with it. Basically it validates
    /// `TestHelper`'s ability to distinguish messages of the same type sent towards helpers
    /// executing multiple same type protocols
    #[tokio::test]
    #[allow(clippy::cast_possible_truncation)]
    pub async fn concurrent_mul() {
        let world = helpers::mock::make_world(QueryId);
        let participants = crate::prss::test::make_three();
        let context = make_context(&world, &participants);
        let mut rand = StepRng::new(1, 1);
        let a = share(Fp31::from(4_u128), &mut rand);
        let b = share(Fp31::from(3_u128), &mut rand);

        let mut multiplications = Vec::new();
        let record_id = RecordId::from(1);

        for i in 1..10_u8 {
            // there is something weird going on the compiler's side. I don't see why we need
            // to use async move as `i` is Copy + Clone, but compiler complains about it not living
            // long enough
            let ctx = &context;
            let f = async move {
                let h0_future = ctx[0]
                    .multiply(record_id, TestStep::Mul1(i))
                    .await
                    .execute(a[0], b[0]);
                let h1_future = ctx[1]
                    .multiply(record_id, TestStep::Mul1(i))
                    .await
                    .execute(a[1], b[1]);
                let h2_future = ctx[2]
                    .multiply(record_id, TestStep::Mul1(i))
                    .await
                    .execute(a[2], b[2]);
                try_join!(h0_future, h1_future, h2_future).unwrap()
            };
            multiplications.push(f);
        }

        let results = join_all(multiplications).await;
        for shares in results {
            assert_eq!(Fp31::from(12_u128), validate_and_reconstruct(shares));
        }
    }

    // #[allow(clippy::cast_possible_truncation)]
    async fn multiply_sync<R: RngCore>(
        context: &[ProtocolContext<'_, TestHelperGateway<TestStep>, TestStep>; 3],
        a: u8,
        b: u8,
        rng: &mut R,
    ) -> Result<u8, BoxError> {
        assert!(a < Fp31::PRIME);
        assert!(b < Fp31::PRIME);

        let a = Fp31::from(u128::from(a));
        let b = Fp31::from(u128::from(b));

        thread_local! {
            static INDEX: AtomicU32 = AtomicU32::default();
        }

        let record_id = INDEX.with(|i| i.fetch_add(1, Ordering::Release)).into();

        let a = share(a, rng);
        let b = share(b, rng);

        let result_shares = tokio::try_join!(
            context[0]
                .multiply(record_id, TestStep::Mul2)
                .await
                .execute(a[0], b[0]),
            context[1]
                .multiply(record_id, TestStep::Mul2)
                .await
                .execute(a[1], b[1]),
            context[2]
                .multiply(record_id, TestStep::Mul2)
                .await
                .execute(a[2], b[2]),
        )?;

        Ok(validate_and_reconstruct(result_shares).into())
    }

    pub fn make_context<'a, S: Step + SpaceIndex>(
        test_world: &'a TestWorld<S>,
        participants: &'a (Participant<S>, Participant<S>, Participant<S>),
    ) -> [ProtocolContext<'a, TestHelperGateway<S>, S>; 3] {
        test_world
            .gateways
            .iter()
            .zip([&participants.0, &participants.1, &participants.2])
            .map(|(gateway, participant)| ProtocolContext::new(participant, gateway))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    /// Shares `input` into 3 replicated secret shares using the provided `rng` implementation
    pub(super) fn share<R: RngCore>(
        input: Fp31,
        rng: &mut R,
    ) -> [ReplicatedSecretSharing<Fp31>; 3] {
        let x1 = Fp31::from(rng.gen_range(0..Fp31::PRIME));
        let x2 = Fp31::from(rng.gen_range(0..Fp31::PRIME));
        let x3 = input - (x1 + x2);

        [
            ReplicatedSecretSharing::new(x1, x2),
            ReplicatedSecretSharing::new(x2, x3),
            ReplicatedSecretSharing::new(x3, x1),
        ]
    }

    pub(super) fn validate_and_reconstruct<T: Field>(
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
