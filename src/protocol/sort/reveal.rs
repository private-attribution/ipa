use crate::{
    error::BoxError,
    field::Field,
    helpers::{
        mesh::{Gateway, Mesh},
        prss::SpaceIndex,
        Direction,
    },
    protocol::{context::ProtocolContext, RecordId, Step},
    secret_sharing::Replicated,
};
use embed_doc_image::embed_doc_image;
use serde::{Deserialize, Serialize};

/// A message sent by each helper when they've revealed their own shares
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AValue<F> {
    a: F,
}

/// This implements reveal algorithm of "Efficient Secure Three-Party Sorting Protocol with an Honest Majority" at communication cost of 3R.
/// Revealing is the protocol that on input a pair of shares, outputs a secret. For simplicity, we
/// consider a simple revealing in which each Pi sends [a]i to Pi+1 and then reconstructs a from [a]i and
/// [a]i−1.
// Input: Each helpers know their own secret shares
// Output: At the end of the protocol, all 3 helpers know a revealed (or opened) secret
#[derive(Debug)]
pub struct Reveal<F> {
    input: Replicated<F>,
}

impl<F: Field> Reveal<F> {
    #[allow(dead_code)]
    pub fn new(input: Replicated<F>) -> Self {
        Self { input }
    }

    /// Steps
    /// Each helper sends their left share to the right helper. The helper then reconstructs their secret by adding the three shares
    /// i.e. their own shares and received share.
    #[embed_doc_image("reveal", "images/sort/reveal.png")]
    #[allow(dead_code)]
    pub async fn execute<M: Mesh, G: Gateway<M, S>, S: Step + SpaceIndex>(
        self,
        ctx: &ProtocolContext<'_, G, S>,
        record_id: RecordId,
        step: S,
    ) -> Result<F, BoxError> {
        let mut channel = ctx.gateway.get_channel(step);

        let inputs = self.input.as_tuple();
        // `to_helper.left` calculates part1 = (input.0 + input.1) - r1 and sends part1 to `to_helper.right`
        channel
            .send(
                channel.identity().peer(Direction::Right),
                record_id,
                AValue { a: inputs.0 },
            )
            .await?;

        // Sleep until `to_helper.left` sends us their part2 value
        let AValue { a } = channel
            .receive(channel.identity().peer(Direction::Left), record_id)
            .await?;

        Ok(inputs.0 + inputs.1 + a)
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::mock::StepRng;
    use tokio::try_join;

    use crate::{
        field::Fp31,
        protocol::{sort::reveal::Reveal, QueryId, RecordId},
        test_fixture::{make_contexts, make_world, share, TestStep, TestWorld},
    };

    #[tokio::test]
    pub async fn reveal() {
        let mut rand = StepRng::new(100, 1);

        let input = Fp31::from(23_u128);
        let share = share(input, &mut rand);
        let record_id = RecordId::from(1);

        let world: TestWorld<TestStep> = make_world(QueryId);
        let context = make_contexts(&world);

        let step = TestStep::Reveal(1);

        let reveal0 = Reveal::new(share[0]);
        let reveal1 = Reveal::new(share[1]);
        let reveal2 = Reveal::new(share[2]);

        let h0_future = reveal0.execute(&context[0], record_id, step);
        let h1_future = reveal1.execute(&context[1], record_id, step);
        let h2_future = reveal2.execute(&context[2], record_id, step);

        let f = try_join!(h0_future, h1_future, h2_future).unwrap();
        assert_eq!(input, f.0);
        assert_eq!(f.0, f.1);
        assert_eq!(f.1, f.2);
    }
}
