use std::iter::{repeat, zip};

use crate::ff::Field;
use crate::protocol::context::ProtocolContext;
use crate::secret_sharing::Replicated;
use crate::{error::BoxError, helpers::Direction, protocol::RecordId};
use embed_doc_image::embed_doc_image;
use futures::future::try_join_all;
use permutation::Permutation;

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
pub async fn reveal<F: Field>(
    ctx: ProtocolContext<'_, F>,
    record_id: RecordId,
    input: Replicated<F>,
) -> Result<F, BoxError> {
    let channel = ctx.mesh();

    channel
        .send(ctx.role().peer(Direction::Right), record_id, input.left())
        .await?;

    // Sleep until `helper's left` sends their share
    let share = channel
        .receive(ctx.role().peer(Direction::Left), record_id)
        .await?;

    Ok(input.left() + input.right() + share)
}

/// Given a vector containing secret shares of a permutation, this returns a revealed permutation.
/// This executes `reveal` protocol on each row of the vector and then constructs a `Permutation` object
/// from the revealed rows.
#[allow(clippy::cast_possible_truncation, clippy::module_name_repetitions)]
pub async fn reveal_a_permutation<F: Field>(
    ctx: ProtocolContext<'_, F>,
    permutation: &mut [Replicated<F>],
) -> Result<Permutation, BoxError> {
    let revealed_permutation = try_join_all(zip(repeat(ctx), permutation).enumerate().map(
        |(index, (ctx, input))| async move { reveal(ctx, RecordId::from(index), *input).await },
    ))
    .await?;
    let mut perms = Vec::new();
    for i in revealed_permutation {
        perms.push(i.as_u128().try_into()?);
    }
    Ok(Permutation::oneline(perms))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::Rng;
    use rand::rngs::mock::StepRng;
    use tokio::try_join;

    use crate::{
        ff::Fp31,
        protocol::{reveal::reveal, QueryId, RecordId},
        test_fixture::{make_contexts, make_world, share, TestWorld},
    };

    #[tokio::test]
    pub async fn simple() {
        let mut rand = StepRng::new(100, 1);
        let mut rng = rand::thread_rng();

        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts::<Fp31>(&world);

        for i in 0..10_u32 {
            let secret = rng.gen::<u128>();

            let input = Fp31::from(secret);
            let share = share(input, &mut rand);

            let record_id = RecordId::from(i);
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
