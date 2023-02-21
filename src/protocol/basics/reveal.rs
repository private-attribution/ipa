use std::iter::{repeat, zip};

use crate::{
    error::Error,
    ff::Field,
    helpers::Direction,
    protocol::{
        context::{Context, MaliciousContext, SemiHonestContext},
        RecordId,
    },
    secret_sharing::{
        replicated::{
            malicious::AdditiveShare as MaliciousReplicated,
            semi_honest::AdditiveShare as Replicated,
        },
        SecretSharing, SharedValue,
    },
};
use async_trait::async_trait;
use embed_doc_image::embed_doc_image;
use futures::future::{try_join, try_join_all};

/// Trait for reveal protocol to open a shared secret to all helpers inside the MPC ring.
#[async_trait]
pub trait Reveal<V: SharedValue> {
    /// Secret sharing type that reveal implementation works with. Note that field type does not
    /// matter - implementations must be able to reveal secret value from any field.
    type Share: SecretSharing<V>;

    /// reveal the secret to all helpers in MPC circuit. Note that after method is called,
    /// it must be assumed that the secret value has been revealed to at least one of the helpers.
    /// Even in case when method never terminates, returns an error, etc.
    async fn reveal(self, record: RecordId, input: &Self::Share) -> Result<V, Error>;
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
impl<F: Field> Reveal<F> for SemiHonestContext<'_, F> {
    type Share = Replicated<F>;

    async fn reveal(self, record_id: RecordId, input: &Self::Share) -> Result<F, Error> {
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
impl<F: Field> Reveal<F> for MaliciousContext<'_, F> {
    type Share = MaliciousReplicated<F>;

    async fn reveal(self, record_id: RecordId, input: &Self::Share) -> Result<F, Error> {
        use crate::secret_sharing::replicated::malicious::ThisCodeIsAuthorizedToDowngradeFromMalicious;

        let (role, channel) = (self.role(), self.mesh());
        let (left, right) = input.x().access_without_downgrade().as_tuple();

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
/// # Errors
/// If we cant convert F to u128
/// # Panics
/// If we cant convert F to u128
pub async fn reveal_permutation<F: Field, S: SecretSharing<F>, C: Context<F, Share = S>>(
    ctx: C,
    permutation: &[S],
) -> Result<Vec<u32>, Error> {
    let ctx = ctx.set_total_records(permutation.len());
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

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use crate::{rand::thread_rng, test_fixture::Runner};
    use futures::future::{try_join, try_join3};
    use proptest::prelude::Rng;
    use std::iter::zip;

    use crate::{
        error::Error,
        ff::{Field, Fp31},
        helpers::Direction,
        protocol::{
            basics::Reveal,
            context::{Context, MaliciousContext},
            malicious::MaliciousValidator,
            RecordId,
        },
        secret_sharing::{
            replicated::malicious::{
                AdditiveShare as MaliciousReplicated, ThisCodeIsAuthorizedToDowngradeFromMalicious,
            },
            IntoShares,
        },
        test_fixture::{join3v, TestWorld},
    };

    #[tokio::test]
    pub async fn simple() -> Result<(), Error> {
        let mut rng = thread_rng();
        let world = TestWorld::new().await;

        let input = rng.gen::<Fp31>();
        let results = world
            .semi_honest(input, |ctx, share| async move {
                ctx.set_total_records(1)
                    .reveal(RecordId::from(0), &share)
                    .await
                    .unwrap()
            })
            .await;

        assert_eq!(input, results[0]);
        assert_eq!(input, results[1]);
        assert_eq!(input, results[2]);

        Ok(())
    }

    #[tokio::test]
    pub async fn malicious() -> Result<(), Error> {
        let mut rng = thread_rng();
        let world = TestWorld::new().await;
        let sh_ctx = world.contexts::<Fp31>();
        let v = sh_ctx.map(MaliciousValidator::new);
        let m_ctx: [_; 3] = v
            .iter()
            .map(|v| v.context().set_total_records(1))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let record_id = RecordId::from(0);
        let input: Fp31 = rng.gen();

        let m_shares = join3v(
            zip(m_ctx.iter(), input.share_with(&mut rng))
                .map(|(m_ctx, share)| async { m_ctx.upgrade(share).await }),
        )
        .await;

        let results = join3v(
            zip(m_ctx.clone().into_iter(), m_shares)
                .map(|(m_ctx, m_share)| async move { m_ctx.reveal(record_id, &m_share).await }),
        )
        .await;

        assert_eq!(input, results[0]);
        assert_eq!(input, results[1]);
        assert_eq!(input, results[2]);

        Ok(())
    }

    #[tokio::test]
    pub async fn malicious_validation_fail() -> Result<(), Error> {
        let mut rng = thread_rng();
        let world = TestWorld::new().await;
        let sh_ctx = world.contexts::<Fp31>();
        let v = sh_ctx.map(MaliciousValidator::new);
        let m_ctx: [_; 3] = v
            .iter()
            .map(|v| v.context().set_total_records(1))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let record_id = RecordId::from(0);
        let input: Fp31 = rng.gen();

        let m_shares = join3v(
            zip(m_ctx.iter(), input.share_with(&mut rng))
                .map(|(m_ctx, share)| async { m_ctx.upgrade(share).await }),
        )
        .await;
        let result = try_join3(
            m_ctx[0].clone().reveal(record_id, &m_shares[0]),
            m_ctx[1].clone().reveal(record_id, &m_shares[1]),
            reveal_with_additive_attack(m_ctx[2].clone(), record_id, &m_shares[2], Fp31::ONE),
        )
        .await;

        assert!(matches!(result, Err(Error::MaliciousRevealFailed)));

        Ok(())
    }

    pub async fn reveal_with_additive_attack<F: Field>(
        ctx: MaliciousContext<'_, F>,
        record_id: RecordId,
        input: &MaliciousReplicated<F>,
        additive_error: F,
    ) -> Result<F, Error> {
        let channel = ctx.mesh();
        let (left, right) = input.x().access_without_downgrade().as_tuple();

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
