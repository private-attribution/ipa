use crate::{
    error::BoxError,
    ff::{Field, Fp2},
    helpers::Direction,
    protocol::{context::ProtocolContext, RecordId},
};

use crate::secret_sharing::SecretSharing;
use futures::future::try_join;

/// This implements a reveal algorithm for an additive binary secret sharing.
/// As this is an additive sharing, each helper has just one boolean share
/// As such, reveal requires each helper to send their share both left and right
/// Put another way, each `P_i` sends `\[a\]_i` to `P_i+1` and `P_i-1`
/// and then reconstructs a from` \[a\]_i`, `\[a\]_i+i` and `\[a\]i−1`.
/// Input: Each helpers know their own secret shares
/// Output: At the end of the protocol, all 3 helpers know a revealed (or opened) secret
#[derive(Debug)]
pub struct RevealAdditiveBinary {}

impl RevealAdditiveBinary {
    #[allow(dead_code)]
    pub async fn execute<S: SecretSharing<F>, F: Field>(
        ctx: ProtocolContext<'_, S, F>,
        record_id: RecordId,
        input: Fp2,
    ) -> Result<Fp2, BoxError> {
        let channel = ctx.mesh();

        // Send share to helper to the left
        let future_left = channel.send(ctx.role().peer(Direction::Left), record_id, input);

        // Send share to helper to the right
        let future_right = channel.send(ctx.role().peer(Direction::Right), record_id, input);

        try_join(future_left, future_right).await?;

        // Sleep until `helper's left` sends their share
        let future_left = channel.receive(ctx.role().peer(Direction::Left), record_id);

        // Sleep until `helper's right` sends their share
        let future_right = channel.receive(ctx.role().peer(Direction::Right), record_id);

        let (share_from_left, share_from_right): (Fp2, Fp2) =
            try_join(future_left, future_right).await?;

        Ok(input ^ share_from_left ^ share_from_right)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::Rng;

    use crate::{
        ff::{Fp2, Fp31},
        protocol::{reveal_additive_binary::RevealAdditiveBinary, QueryId, RecordId},
        test_fixture::{make_contexts, make_world, TestWorld},
    };
    use futures::future::try_join_all;

    #[tokio::test]
    pub async fn reveal() {
        let mut rng = rand::thread_rng();

        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts::<Fp31>(&world);
        let [c0, c1, c2] = ctx;

        let mut bools: Vec<bool> = Vec::with_capacity(40);

        let inputs = (0..10_u32).into_iter().map(|i| {
            let b0 = rng.gen::<bool>();
            let b1 = rng.gen::<bool>();
            let b2 = rng.gen::<bool>();
            bools.push((b0 ^ b1) ^ b2);

            (i, b0, b1, b2, c0.clone(), c1.clone(), c2.clone())
        });

        let futures = inputs
            .into_iter()
            .map(|(i, b0, b1, b2, c0, c1, c2)| async move {
                let record_id = RecordId::from(i);

                let h0_future = RevealAdditiveBinary::execute(c0, record_id, Fp2::from(b0));
                let h1_future = RevealAdditiveBinary::execute(c1, record_id, Fp2::from(b1));
                let h2_future = RevealAdditiveBinary::execute(c2, record_id, Fp2::from(b2));

                try_join_all(vec![h0_future, h1_future, h2_future]).await
            });

        let results = try_join_all(futures).await.unwrap();

        for i in 0..10 {
            let correct_result = Fp2::from(bools[i]);

            assert_eq!(correct_result, results[i][0]);
            assert_eq!(correct_result, results[i][1]);
            assert_eq!(correct_result, results[i][2]);
        }
    }
}
