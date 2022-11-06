use std::iter::{repeat, zip};

use crate::ff::Field;
use crate::protocol::context::ProtocolContext;
use crate::secret_sharing::Replicated;
use crate::{
    error::{BoxError, Error},
    helpers::Direction,
    protocol::RecordId,
};
use embed_doc_image::embed_doc_image;
use futures::future::{try_join, try_join_all};
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
    ctx: ProtocolContext<'_, Replicated<F>, F>,
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

#[allow(dead_code)]
#[allow(clippy::module_name_repetitions)]
pub async fn reveal_malicious<F: Field>(
    ctx: ProtocolContext<'_, F>,
    record_id: RecordId,
    input: Replicated<F>,
) -> Result<F, BoxError> {
    let channel = ctx.mesh();

    // Send share to helpers to the right and left
    try_join(
        channel.send(ctx.role().peer(Direction::Left), record_id, input.right()),
        channel.send(ctx.role().peer(Direction::Right), record_id, input.left()),
    )
    .await?;

    let (share_from_left, share_from_right): (F, F) = try_join(
        channel.receive(ctx.role().peer(Direction::Left), record_id),
        channel.receive(ctx.role().peer(Direction::Right), record_id),
    )
    .await?;

    if share_from_left == share_from_right {
        Ok(input.left() + input.right() + share_from_left)
    } else {
        Err(Box::new(Error::MaliciousRevealFailed))
    }
}

/// Given a vector containing secret shares of a permutation, this returns a revealed permutation.
/// This executes `reveal` protocol on each row of the vector and then constructs a `Permutation` object
/// from the revealed rows.
#[allow(clippy::module_name_repetitions)]
pub async fn reveal_permutation<F: Field>(
    ctx: ProtocolContext<'_, Replicated<F>, F>,
    permutation: &[Replicated<F>],
) -> Result<Permutation, BoxError> {
    let revealed_permutation = try_join_all(zip(repeat(ctx), permutation).enumerate().map(
        |(index, (ctx, input))| async move {
            let reveal_value = reveal(ctx, RecordId::from(index), *input).await;

            // safety: we wouldn't use fields larger than 64 bits and there are checks that enforce it
            // in the field module
            reveal_value.map(|val| val.as_u128().try_into().unwrap())
        },
    ))
    .await?;

    Ok(Permutation::oneline(revealed_permutation))
}

#[cfg(test)]
mod tests {
    use futures::future::{try_join, try_join_all};
    use proptest::prelude::Rng;
    use tokio::try_join;

    use crate::{
        error::BoxError,
        ff::{Field, Fp31},
        helpers::Direction,
        protocol::{
            context::ProtocolContext,
            reveal::{reveal, reveal_malicious},
            QueryId, RecordId,
        },
        secret_sharing::Replicated,
        test_fixture::{make_contexts, make_world, share, TestWorld},
    };

    #[tokio::test]
    pub async fn simple() -> Result<(), BoxError> {
        let mut rng = rand::thread_rng();
        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts::<Fp31>(&world);

        for i in 0..10_u32 {
            let secret = rng.gen::<u128>();
            let input = Fp31::from(secret);
            let share = share(input, &mut rng);
            let record_id = RecordId::from(i);
            let results = try_join_all(vec![
                reveal(ctx[0].clone(), record_id, share[0]),
                reveal(ctx[1].clone(), record_id, share[1]),
                reveal(ctx[2].clone(), record_id, share[2]),
            ])
            .await?;

            assert_eq!(input, results[0]);
            assert_eq!(input, results[1]);
            assert_eq!(input, results[2]);
        }
        Ok(())
    }

    #[tokio::test]
    pub async fn malicious() -> Result<(), BoxError> {
        let mut rng = rand::thread_rng();
        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts::<Fp31>(&world);

        for i in 0..10_u32 {
            let secret = rng.gen::<u128>();
            let input = Fp31::from(secret);
            let share = share(input, &mut rng);
            let record_id = RecordId::from(i);
            let results = try_join_all(vec![
                reveal_malicious(ctx[0].clone(), record_id, share[0]),
                reveal_malicious(ctx[1].clone(), record_id, share[1]),
                reveal_malicious(ctx[2].clone(), record_id, share[2]),
            ])
            .await?;

            assert_eq!(input, results[0]);
            assert_eq!(input, results[1]);
            assert_eq!(input, results[2]);
        }
        Ok(())
    }

    #[tokio::test]
    pub async fn malicious_validation_fail() -> Result<(), BoxError> {
        let mut rng = rand::thread_rng();
        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts::<Fp31>(&world);

        for i in 0..10_u32 {
            let secret = rng.gen::<u128>();
            let input = Fp31::from(secret);
            let share = share(input, &mut rng);
            let record_id = RecordId::from(i);
            let result = try_join!(
                reveal_malicious(ctx[0].clone(), record_id, share[0]),
                reveal_malicious(ctx[1].clone(), record_id, share[1]),
                reveal_with_additive_attack(ctx[2].clone(), record_id, share[2], Fp31::ONE),
            );

            match result {
                Ok(_) => panic!("should not work"),
                Err(e) => assert_eq!(format!("{}", e), "malicious reveal failed"),
            }
        }
        Ok(())
    }

    pub async fn reveal_with_additive_attack<F: Field>(
        ctx: ProtocolContext<'_, F>,
        record_id: RecordId,
        input: Replicated<F>,
        additive_error: F,
    ) -> Result<F, BoxError> {
        let channel = ctx.mesh();

        // Send share to helpers to the right and left
        try_join(
            channel.send(ctx.role().peer(Direction::Left), record_id, input.right()),
            channel.send(
                ctx.role().peer(Direction::Right),
                record_id,
                input.left() + additive_error,
            ),
        )
        .await?;

        let (share_from_left, _share_from_right): (F, F) = try_join(
            channel.receive(ctx.role().peer(Direction::Left), record_id),
            channel.receive(ctx.role().peer(Direction::Right), record_id),
        )
        .await?;

        Ok(input.left() + input.right() + share_from_left)
    }
}
