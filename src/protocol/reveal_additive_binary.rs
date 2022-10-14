use crate::{
    error::BoxError,
    helpers::{fabric::Network, prss::SpaceIndex, Direction},
    protocol::{context::ProtocolContext, RecordId, Step},
};

use serde::{Deserialize, Serialize};

/// A message sent by each helper when they've revealed their own shares
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct RevealValue {
    share: bool,
}

/// This implements reveal algorithm
/// As this is an additive sharing, each helper has just one boolean share
/// As such, reveal requires each helper to send their share both left and right
/// Put another way, each `P_i` sends `\[a\]_i` to `P_i+1` and `P_i-1`
/// and then reconstructs a from` \[a\]_i`, `\[a\]_i+i` and `\[a\]i−1`.
// Input: Each helpers know their own secret shares
// Output: At the end of the protocol, all 3 helpers know a revealed (or opened) secret
#[derive(Debug)]
pub struct RevealAdditiveBinary {}

impl RevealAdditiveBinary {
    #[allow(dead_code)]
    pub async fn execute<S: Step + SpaceIndex, N: Network<S>>(
        ctx: &ProtocolContext<'_, S, N>,
        step: S,
        record_id: RecordId,
        input: bool,
    ) -> Result<bool, BoxError> {
        let mut channel = ctx.gateway.get_channel(step);

        channel
            .send(
                channel.identity().peer(Direction::Left),
                record_id,
                RevealValue { share: input },
            )
            .await?;

        channel
            .send(
                channel.identity().peer(Direction::Right),
                record_id,
                RevealValue { share: input },
            )
            .await?;

        // Sleep until `helper's left` sends their share
        let share_from_left: RevealValue = channel
            .receive(channel.identity().peer(Direction::Left), record_id)
            .await?;

        // Sleep until `helper's right` sends their share
        let share_from_right: RevealValue = channel
            .receive(channel.identity().peer(Direction::Right), record_id)
            .await?;

        Ok(input ^ share_from_left.share ^ share_from_right.share)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::Rng;
    use tokio::try_join;

    use crate::{
        protocol::{reveal_additive_binary::RevealAdditiveBinary, QueryId, RecordId},
        test_fixture::{make_contexts, make_world, TestStep, TestWorld},
    };

    #[tokio::test]
    pub async fn reveal() {
        let mut rng = rand::thread_rng();

        for i in 0..10 {
            let b0 = rng.gen::<bool>();
            let b1 = rng.gen::<bool>();
            let b2 = rng.gen::<bool>();

            let input = b0 ^ b1 ^ b2;
            let record_id = RecordId::from(i);

            let world: TestWorld<TestStep> = make_world(QueryId);
            let ctx = make_contexts(&world);

            let step = TestStep::Reveal(1);

            let h0_future = RevealAdditiveBinary::execute(&ctx[0], step, record_id, b0);
            let h1_future = RevealAdditiveBinary::execute(&ctx[1], step, record_id, b1);
            let h2_future = RevealAdditiveBinary::execute(&ctx[2], step, record_id, b2);

            let f = try_join!(h0_future, h1_future, h2_future).unwrap();
            assert_eq!(input, f.0);
            assert_eq!(input, f.1);
            assert_eq!(input, f.2);
        }
    }
}
