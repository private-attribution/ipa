use crate::helpers::fabric::Network;
use crate::protocol::context::ProtocolContext;
use crate::{
    error::BoxError, field::Field, helpers::Direction, protocol::RecordId,
    secret_sharing::Replicated,
};
use embed_doc_image::embed_doc_image;
use serde::{Deserialize, Serialize};

/// This implements a reveal algorithm
/// For simplicity, we consider a simple revealing in which each `P_i` sends `\[a\]_i` to `P_i+1` after which
/// each helper has all three shares and can reconstruct `a`
///
/// Input: Each helpers know their own secret shares
/// Output: At the end of the protocol, all 3 helpers know a revealed (or opened) secret
///
/// Steps
/// ![Reveal steps][reveal]
/// Each helper sends their left share to the right helper. The helper then reconstructs their secret by adding the three shares
/// i.e. their own shares and received share.
#[embed_doc_image("reveal", "images/reveal.png")]
#[allow(dead_code)]
pub async fn reveal<F: Field, N: Network>(
    ctx: ProtocolContext<'_, N>,
    record_id: RecordId,
    input: Replicated<F>,
) -> Result<F, BoxError> {
    let channel = ctx.mesh();

    let inputs = input.as_tuple();
    channel
        .send(
            ctx.role().peer(Direction::Right),
            record_id,
            inputs.0,
        )
        .await?;

    // Sleep until `helper's left` sends their share
    let share: F = channel
        .receive(ctx.role().peer(Direction::Left), record_id)
        .await?;

    Ok(inputs.0 + inputs.1 + share)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::Rng;
    use rand::rngs::mock::StepRng;
    use tokio::try_join;

    use crate::{
        field::Fp31,
        protocol::{reveal::reveal, QueryId, RecordId},
        test_fixture::{make_contexts, make_world, share, TestWorld},
    };

    #[tokio::test]
    pub async fn simple() {
        let mut rand = StepRng::new(100, 1);

        let mut rng = rand::thread_rng();

        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts(&world);

        for i in 0..10 {
            let secret = rng.gen::<u128>();

            let input = Fp31::from(secret);
            let share = share(input, &mut rand);

            let record_id = RecordId::from(0);
            let iteration = format!("{}", i);

            let h0_future = reveal(ctx[0].narrow(&iteration), record_id, share[0]);
            let h1_future = reveal(ctx[1].narrow(&iteration), record_id, share[1]);
            let h2_future = reveal(ctx[2].narrow(&iteration), record_id, share[2]);

            let f = try_join!(h0_future, h1_future, h2_future).unwrap();

            assert_eq!(input, f.0);
            assert_eq!(input, f.1);
            assert_eq!(input, f.2);
        }
    }
}
