use crate::helpers::fabric::Network;
use crate::protocol::context::ProtocolContext;
use crate::{
    error::BoxError, field::Field, helpers::Direction, protocol::RecordId,
    secret_sharing::Replicated,
};
use embed_doc_image::embed_doc_image;
use serde::{Deserialize, Serialize};

/// A message sent by each helper when they've revealed their own shares
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct RevealValue<F> {
    share: F,
}

/// This implements reveal algorithm
/// For simplicity, we consider a simple revealing in which each Pi sends \[a\]i to Pi+1 and then reconstructs a from \[a\]i and
/// \[a\]i−1.
// Input: Each helpers know their own secret shares
// Output: At the end of the protocol, all 3 helpers know a revealed (or opened) secret
#[derive(Debug)]
pub struct Reveal<'a, 'b, N> {
    context: &'a ProtocolContext<'b, N>,
    record_id: RecordId,
}

impl<'a, 'b: 'a, N: Network> Reveal<'a, 'b, N> {
    #[allow(dead_code)]
    // We would want reveal constructors to be hidden from IPA code. Only ProtocolContext should be able to instantiate it and we
    // can verify that the call site is allowed to reveal by checking the step variable.
    pub(in crate::protocol) fn new(
        context: &'a ProtocolContext<'b, N>,
        record_id: RecordId,
    ) -> Self {
        Self { context, record_id }
    }

    #[embed_doc_image("reveal", "images/sort/reveal.png")]
    /// Steps
    /// ![Reveal steps][reveal]
    /// Each helper sends their left share to the right helper. The helper then reconstructs their secret by adding the three shares
    /// i.e. their own shares and received share.
    #[allow(dead_code)]
    pub async fn execute<F: Field>(self, input: Replicated<F>) -> Result<F, BoxError> {
        let mut channel = self.context.mesh();

        let inputs = input.as_tuple();
        channel
            .send(
                channel.identity().peer(Direction::Right),
                self.record_id,
                RevealValue { share: inputs.0 },
            )
            .await?;

        // Sleep until `helper's left` sends their share
        let RevealValue { share } = channel
            .receive(channel.identity().peer(Direction::Left), self.record_id)
            .await?;

        Ok(inputs.0 + inputs.1 + share)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::Rng;
    use rand::rngs::mock::StepRng;
    use tokio::try_join;

    use crate::{
        field::Fp31,
        protocol::{QueryId, RecordId},
        test_fixture::{make_contexts, make_world, share, TestWorld},
    };

    #[tokio::test]
    pub async fn reveal() {
        let mut rand = StepRng::new(100, 1);

        let mut rng = rand::thread_rng();

        for _ in 0..10 {
            let secret = rng.gen::<u128>();

            let input = Fp31::from(secret);
            let share = share(input, &mut rand);
            let record_id = RecordId::from(1);

            let world: TestWorld = make_world(QueryId);
            let ctx = make_contexts(&world);

            let h0_future = ctx[0].reveal(record_id).execute(share[0]);

            let h1_future = ctx[1].reveal(record_id).execute(share[1]);
            let h2_future = ctx[2].reveal(record_id).execute(share[2]);

            let f = try_join!(h0_future, h1_future, h2_future).unwrap();
            assert_eq!(input, f.0);
            assert_eq!(f.0, f.1);
            assert_eq!(f.1, f.2);
        }
    }
}
