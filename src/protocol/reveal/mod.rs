use std::iter::{repeat, zip};

use crate::ff::Field;
use crate::protocol::context::ProtocolContext;
use crate::secret_sharing::{MaliciousReplicated, Replicated, SecretSharing};
use crate::{error::Error, helpers::Direction, protocol::RecordId};
use async_trait::async_trait;
use embed_doc_image::embed_doc_image;
use futures::future::{try_join, try_join_all};

/// Trait for reveal protocol to open a shared secret to all helpers inside the MPC ring.
#[async_trait]
pub trait Reveal {
    /// Secret sharing type that reveal implementation works with. Note that field type does not
    /// matter - implementations must be able to reveal secret value from any field.
    type Share<F: Field>: SecretSharing<F>;

    /// reveal the secret to all helpers in MPC circuit. Note that after method is called,
    /// it must be assumed that the secret value has been revealed to at least one of the helpers.
    /// Even in case when method never terminates, returns an error, etc.
    async fn reveal<F: Field>(self, record: RecordId, input: &Self::Share<F>) -> Result<F, Error>;
}

/// This implements a semi-honest reveal algorithm for replicated secret sharing.
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
#[async_trait]
#[embed_doc_image("reveal", "images/reveal.png")]
impl<G: Field> Reveal for ProtocolContext<'_, Replicated<G>, G> {
    type Share<F: Field> = Replicated<F>;

    async fn reveal<F: Field>(
        self,
        record_id: RecordId,
        input: &Self::Share<F>,
    ) -> Result<F, Error> {
        let (role, channel) = (self.role(), self.mesh());
        let (left, right) = input.as_tuple();

        channel
            .send(role.peer(Direction::Right), record_id, left)
            .await?;

        // Sleep until `helper's left` sends their share
        let share = channel
            .receive(role.peer(Direction::Left), record_id)
            .await?;

        Ok(left + right + share)
    }
}

/// This implements the malicious reveal protocol over replicated secret sharings.
/// It works similarly to semi-honest reveal, the key difference is that each helper sends its share
/// to both helpers (right and left) and upon receiving 2 shares from peers it validates that they
/// indeed match.
#[async_trait]
impl<G: Field> Reveal for ProtocolContext<'_, MaliciousReplicated<G>, G> {
    type Share<F: Field> = MaliciousReplicated<F>;

    async fn reveal<F: Field>(
        self,
        record_id: RecordId,
        input: &Self::Share<F>,
    ) -> Result<F, Error> {
        let (role, channel) = (self.role(), self.mesh());
        let (left, right) = input.x().as_tuple();

        // Send share to helpers to the right and left
        try_join(
            channel.send(role.peer(Direction::Left), record_id, right),
            channel.send(role.peer(Direction::Right), record_id, left),
        )
        .await?;

        let (share_from_left, share_from_right) = try_join(
            channel.receive(role.peer(Direction::Left), record_id),
            channel.receive(role.peer(Direction::Right), record_id),
        )
        .await?;

        if share_from_left == share_from_right {
            Ok(left + right + share_from_left)
        } else {
            Err(Error::MaliciousRevealFailed)
        }
    }
}

/// Given a vector containing secret shares of a permutation, this returns a revealed permutation.
/// This executes `reveal` protocol on each row of the vector and then constructs a `Permutation` object
/// from the revealed rows.
pub async fn reveal_permutation<F: Field>(
    ctx: ProtocolContext<'_, Replicated<F>, F>,
    permutation: &[Replicated<F>],
) -> Result<Vec<u32>, Error> {
    let revealed_permutation = try_join_all(zip(repeat(ctx), permutation).enumerate().map(
        |(index, (ctx, input))| async move {
            let reveal_value = ctx.reveal(RecordId::from(index), input).await;

            // safety: we wouldn't use fields larger than 64 bits and there are checks that enforce it
            // in the field module
            reveal_value.map(|val| val.as_u128().try_into().unwrap())
        },
    ))
    .await?;

    Ok(revealed_permutation)
}

#[cfg(test)]
mod tests {
    use futures::future::{try_join, try_join_all};
    use proptest::prelude::Rng;
    use std::iter::{repeat, zip};

    use crate::{
        error::Error,
        ff::{Field, Fp31},
        helpers::{Direction, Role},
        protocol::reveal::Reveal,
        protocol::{context::ProtocolContext, QueryId, RecordId},
        secret_sharing::MaliciousReplicated,
        test_fixture::{
            make_contexts, make_malicious_contexts, make_world, share, validate_circuit, TestWorld,
        },
    };

    #[tokio::test]
    pub async fn simple() -> Result<(), Error> {
        let mut rng = rand::thread_rng();
        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts::<Fp31>(&world);

        for i in 0..10_u32 {
            let secret = rng.gen::<u128>();
            let input = Fp31::from(secret);
            let share = share(input, &mut rng);
            let record_id = RecordId::from(i);
            let results = try_join_all(vec![
                ctx[0].clone().reveal(record_id, &share[0]),
                ctx[1].clone().reveal(record_id, &share[1]),
                ctx[2].clone().reveal(record_id, &share[2]),
            ])
            .await?;

            assert_eq!(input, results[0]);
            assert_eq!(input, results[1]);
            assert_eq!(input, results[2]);
        }
        Ok(())
    }

    #[tokio::test]
    pub async fn malicious() -> Result<(), Error> {
        let mut rng = rand::thread_rng();
        let world: TestWorld = make_world(QueryId);

        let mut inputs = Vec::with_capacity(10);
        for _ in 0..10 {
            inputs.push(rng.gen::<Fp31>());
        }
        let (contexts, validators, malicious_inputs) =
            make_malicious_contexts(&world, &inputs, &mut rng).await;

        let reveals =
            try_join_all(
                zip(contexts.iter(), malicious_inputs).map(|(ctx, input)| async move {
                    try_join_all(zip(repeat(ctx), input).enumerate().map(
                        |(i, (ctx, x))| async move {
                            ctx.narrow("reveal").reveal(RecordId::from(i), &x).await
                        },
                    ))
                    .await
                }),
            )
            .await?;

        for (i, input) in inputs.iter().enumerate() {
            assert_eq!(input, &reveals[0][i]);
            assert_eq!(input, &reveals[1][i]);
            assert_eq!(input, &reveals[2][i]);
        }

        validate_circuit(contexts, validators).await?;

        Ok(())
    }

    #[tokio::test]
    pub async fn malicious_validation_fail() -> Result<(), Error> {
        let mut rng = rand::thread_rng();
        let world: TestWorld = make_world(QueryId);

        let mut inputs = Vec::with_capacity(10);
        for _ in 0..10 {
            inputs.push(rng.gen::<Fp31>());
        }
        let (contexts, validators, malicious_inputs) =
            make_malicious_contexts(&world, &inputs, &mut rng).await;

        let reveals =
            try_join_all(
                zip(contexts.iter(), malicious_inputs).map(|(ctx, input)| async move {
                    try_join_all(zip(repeat(ctx), input).enumerate().map(
                        |(i, (ctx, x))| async move {
                            let record_id = RecordId::from(i);
                            if ctx.role() == Role::H3 {
                                reveal_with_additive_attack(
                                    ctx.narrow("reveal"),
                                    record_id,
                                    &x,
                                    Fp31::ONE,
                                )
                                .await
                            } else {
                                ctx.narrow("reveal").reveal(record_id, &x).await
                            }
                        },
                    ))
                    .await
                }),
            )
            .await;

        assert!(matches!(reveals, Err(Error::MaliciousRevealFailed)));

        validate_circuit(contexts, validators).await?;

        Ok(())
    }

    pub async fn reveal_with_additive_attack<F: Field>(
        ctx: ProtocolContext<'_, MaliciousReplicated<F>, F>,
        record_id: RecordId,
        input: &MaliciousReplicated<F>,
        additive_error: F,
    ) -> Result<F, Error> {
        let channel = ctx.mesh();
        let (left, right) = input.x().as_tuple();

        // Send share to helpers to the right and left
        try_join(
            channel.send(ctx.role().peer(Direction::Left), record_id, right),
            channel.send(
                ctx.role().peer(Direction::Right),
                record_id,
                left + additive_error,
            ),
        )
        .await?;

        let (share_from_left, _share_from_right): (F, F) = try_join(
            channel.receive(ctx.role().peer(Direction::Left), record_id),
            channel.receive(ctx.role().peer(Direction::Right), record_id),
        )
        .await?;

        Ok(left + right + share_from_left)
    }
}
