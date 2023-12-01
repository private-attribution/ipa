use std::iter::{repeat, zip};

use async_trait::async_trait;
use embed_doc_image::embed_doc_image;
use futures::future::try_join;

use crate::{
    error::Error,
    ff::Field,
    helpers::Direction,
    protocol::{
        context::{Context, UpgradedMaliciousContext},
        sort::generate_permutation::ShuffledPermutationWrapper,
        NoRecord, RecordBinding, RecordId,
    },
    secret_sharing::{
        replicated::{
            malicious::{AdditiveShare as MaliciousReplicated, ExtendableField},
            semi_honest::AdditiveShare as Replicated,
        },
        SecretSharing, SharedValue,
    },
};

/// Trait for reveal protocol to open a shared secret to all helpers inside the MPC ring.
#[async_trait]
pub trait Reveal<C: Context, B: RecordBinding>: Sized {
    type Output;
    /// reveal the secret to all helpers in MPC circuit. Note that after method is called,
    /// it must be assumed that the secret value has been revealed to at least one of the helpers.
    /// Even in case when method never terminates, returns an error, etc.
    async fn reveal<'fut>(&self, ctx: C, record_binding: B) -> Result<Self::Output, Error>
    where
        C: 'fut;
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
impl<C: Context, V: SharedValue> Reveal<C, RecordId> for Replicated<V> {
    type Output = V;

    async fn reveal<'fut>(&self, ctx: C, record_id: RecordId) -> Result<V, Error>
    where
        C: 'fut,
    {
        let (left, right) = self.as_tuple();

        ctx.send_channel(ctx.role().peer(Direction::Right))
            .send(record_id, left)
            .await?;

        // Sleep until `helper's left` sends their share
        let share = ctx
            .recv_channel(ctx.role().peer(Direction::Left))
            .receive(record_id)
            .await?;

        Ok(left + right + share)
    }
}

/// This implements the malicious reveal protocol over replicated secret sharings.
/// It works similarly to semi-honest reveal, the key difference is that each helper sends its share
/// to both helpers (right and left) and upon receiving 2 shares from peers it validates that they
/// indeed match.
#[async_trait]
impl<'a, F: ExtendableField> Reveal<UpgradedMaliciousContext<'a, F>, RecordId>
    for MaliciousReplicated<F>
{
    type Output = F;

    async fn reveal<'fut>(
        &self,
        ctx: UpgradedMaliciousContext<'a, F>,
        record_id: RecordId,
    ) -> Result<F, Error>
    where
        UpgradedMaliciousContext<'a, F>: 'fut,
    {
        use crate::secret_sharing::replicated::malicious::ThisCodeIsAuthorizedToDowngradeFromMalicious;

        let (left, right) = self.x().access_without_downgrade().as_tuple();
        let left_sender = ctx.send_channel(ctx.role().peer(Direction::Left));
        let left_receiver = ctx.recv_channel::<F>(ctx.role().peer(Direction::Left));
        let right_sender = ctx.send_channel(ctx.role().peer(Direction::Right));
        let right_receiver = ctx.recv_channel::<F>(ctx.role().peer(Direction::Right));

        // Send share to helpers to the right and left
        try_join(
            left_sender.send(record_id, right),
            right_sender.send(record_id, left),
        )
        .await?;

        let (share_from_left, share_from_right) = try_join(
            left_receiver.receive(record_id),
            right_receiver.receive(record_id),
        )
        .await?;

        if share_from_left == share_from_right {
            Ok(left + right + share_from_left)
        } else {
            Err(Error::MaliciousRevealFailed)
        }
    }
}

#[async_trait]
impl<F, S, C> Reveal<C, NoRecord> for ShuffledPermutationWrapper<S, C>
where
    F: Field,
    S: SecretSharing<F> + Reveal<C, RecordId, Output = F>,
    C: Context,
{
    type Output = Vec<u32>;

    /// Given a vector containing secret shares of a permutation, this returns a revealed permutation.
    /// This executes `reveal` protocol on each row of the vector and then constructs a `Permutation` object
    /// from the revealed rows.
    /// # Errors
    /// If we cant convert F to u128
    /// # Panics
    /// If we cant convert F to u128
    async fn reveal<'fut>(&self, ctx: C, _: NoRecord) -> Result<Vec<u32>, Error> {
        let ctx_ref = &ctx;
        let ctx = ctx.set_total_records(self.perm.len());
        let revealed_permutation = ctx_ref
            .try_join(zip(repeat(ctx), self.perm.iter()).enumerate().map(
                |(index, (ctx, value))| async move {
                    let reveal_value = value.reveal(ctx, RecordId::from(index)).await;

                    // safety: we wouldn't use fields larger than 64 bits and there are checks that enforce it
                    // in the field module
                    reveal_value.map(|val| val.as_u128().try_into().unwrap())
                },
            ))
            .await?;

        Ok(revealed_permutation)
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::iter::zip;

    use futures::future::{try_join, try_join3};

    use crate::{
        error::Error,
        ff::{Field, Fp31},
        helpers::Direction,
        protocol::{
            basics::Reveal,
            context::{
                Context, UpgradableContext, UpgradedContext, UpgradedMaliciousContext, Validator,
            },
            RecordId,
        },
        rand::{thread_rng, Rng},
        secret_sharing::{
            replicated::malicious::{
                AdditiveShare as MaliciousReplicated, ExtendableField,
                ThisCodeIsAuthorizedToDowngradeFromMalicious,
            },
            IntoShares,
        },
        test_fixture::{join3v, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn simple() -> Result<(), Error> {
        let mut rng = thread_rng();
        let world = TestWorld::default();

        let input = rng.gen::<Fp31>();
        let results = world
            .semi_honest(input, |ctx, share| async move {
                share
                    .reveal(ctx.set_total_records(1), RecordId::from(0))
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
        let world = TestWorld::default();
        let sh_ctx = world.malicious_contexts();
        let v = sh_ctx.map(UpgradableContext::validator);
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
                .map(|(m_ctx, m_share)| async move { m_share.reveal(m_ctx, record_id).await }),
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
        let world = TestWorld::default();
        let sh_ctx = world.malicious_contexts();
        let v = sh_ctx.map(UpgradableContext::validator);
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
            m_shares[0].reveal(m_ctx[0].clone(), record_id),
            m_shares[1].reveal(m_ctx[1].clone(), record_id),
            reveal_with_additive_attack(m_ctx[2].clone(), record_id, &m_shares[2], Fp31::ONE),
        )
        .await;

        assert!(matches!(result, Err(Error::MaliciousRevealFailed)));

        Ok(())
    }

    pub async fn reveal_with_additive_attack<F: ExtendableField>(
        ctx: UpgradedMaliciousContext<'_, F>,
        record_id: RecordId,
        input: &MaliciousReplicated<F>,
        additive_error: F,
    ) -> Result<F, Error> {
        let (left, right) = input.x().access_without_downgrade().as_tuple();
        let left_sender = ctx.send_channel(ctx.role().peer(Direction::Left));
        let right_sender = ctx.send_channel(ctx.role().peer(Direction::Right));
        let left_recv = ctx.recv_channel(ctx.role().peer(Direction::Left));
        let right_recv = ctx.recv_channel(ctx.role().peer(Direction::Right));

        // Send share to helpers to the right and left
        try_join(
            left_sender.send(record_id, right),
            right_sender.send(record_id, left + additive_error),
        )
        .await?;

        let (share_from_left, _share_from_right): (F, F) =
            try_join(left_recv.receive(record_id), right_recv.receive(record_id)).await?;

        Ok(left + right + share_from_left)
    }
}
