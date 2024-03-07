use async_trait::async_trait;
use embed_doc_image::embed_doc_image;

use crate::{
    error::Error,
    helpers::{Direction, Role},
    protocol::{context::Context, RecordId},
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, SharedValue, Vectorizable,
    },
};
#[cfg(feature = "descriptive-gate")]
use crate::{
    protocol::context::UpgradedMaliciousContext,
    secret_sharing::replicated::malicious::{
        AdditiveShare as MaliciousReplicated, ExtendableField,
    },
};

/// Trait for reveal protocol to open a shared secret to all helpers inside the MPC ring.
#[async_trait]
pub trait Reveal<C: Context, const N: usize>: Sized {
    type Output;
    /// reveal the secret to all helpers in MPC circuit. Note that after method is called,
    /// it must be assumed that the secret value has been revealed to at least one of the helpers.
    /// Even in case when method never terminates, returns an error, etc.
    async fn reveal<'fut>(&self, ctx: C, record_id: RecordId) -> Result<Self::Output, Error>
    where
        C: 'fut;

    /// partial reveal protocol to open a shared secret to all helpers except helper `left_out` inside the MPC ring.
    async fn partial_reveal<'fut>(
        &self,
        ctx: C,
        record_id: RecordId,
        left_out: Role,
    ) -> Result<Option<Self::Output>, Error>
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
impl<C: Context, V: SharedValue + Vectorizable<N>, const N: usize> Reveal<C, N>
    for Replicated<V, N>
{
    type Output = <V as Vectorizable<N>>::Array;

    async fn reveal<'fut>(
        &self,
        ctx: C,
        record_id: RecordId,
    ) -> Result<<V as Vectorizable<N>>::Array, Error>
    where
        C: 'fut,
    {
        let left = self.left_arr();
        let right = self.right_arr();

        ctx.send_channel::<<V as Vectorizable<N>>::Array>(ctx.role().peer(Direction::Right))
            .send(record_id, left)
            .await?;

        // Sleep until `helper's left` sends their share
        let share: <V as Vectorizable<N>>::Array = ctx
            .recv_channel(ctx.role().peer(Direction::Left))
            .receive(record_id)
            .await?;

        Ok(share + left + right)
    }

    /// TODO: implement reveal through partial reveal where `left_out` is optional
    async fn partial_reveal<'fut>(
        &self,
        ctx: C,
        record_id: RecordId,
        left_out: Role,
    ) -> Result<Option<<V as Vectorizable<N>>::Array>, Error>
    where
        C: 'fut,
    {
        let left = self.left_arr();
        let right = self.right_arr();

        // send except to left_out
        if ctx.role().peer(Direction::Right) != left_out {
            ctx.send_channel::<<V as Vectorizable<N>>::Array>(ctx.role().peer(Direction::Right))
                .send(record_id, left)
                .await?;
        }

        if ctx.role() == left_out {
            Ok(None)
        } else {
            let share: <V as Vectorizable<N>>::Array = ctx
                .recv_channel(ctx.role().peer(Direction::Left))
                .receive(record_id)
                .await?;

            Ok(Some(share + left + right))
        }
    }
}

/// This implements the malicious reveal protocol over replicated secret sharings.
/// It works similarly to semi-honest reveal, the key difference is that each helper sends its share
/// to both helpers (right and left) and upon receiving 2 shares from peers it validates that they
/// indeed match.
#[cfg(feature = "descriptive-gate")]
#[async_trait]
impl<'a, F: ExtendableField> Reveal<UpgradedMaliciousContext<'a, F>, 1> for MaliciousReplicated<F> {
    type Output = <F as Vectorizable<1>>::Array;

    async fn reveal<'fut>(
        &self,
        ctx: UpgradedMaliciousContext<'a, F>,
        record_id: RecordId,
    ) -> Result<<F as Vectorizable<1>>::Array, Error>
    where
        UpgradedMaliciousContext<'a, F>: 'fut,
    {
        use futures::future::try_join;

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
            Ok((left + right + share_from_left).into_array())
        } else {
            Err(Error::MaliciousRevealFailed)
        }
    }

    async fn partial_reveal<'fut>(
        &self,
        ctx: UpgradedMaliciousContext<'a, F>,
        record_id: RecordId,
        left_out: Role,
    ) -> Result<Option<<F as Vectorizable<1>>::Array>, Error>
    where
        UpgradedMaliciousContext<'a, F>: 'fut,
    {
        use futures::future::try_join;

        use crate::secret_sharing::replicated::malicious::ThisCodeIsAuthorizedToDowngradeFromMalicious;

        let (left, right) = self.x().access_without_downgrade().as_tuple();
        let left_sender = ctx.send_channel(ctx.role().peer(Direction::Left));
        let left_receiver = ctx.recv_channel::<F>(ctx.role().peer(Direction::Left));
        let right_sender = ctx.send_channel(ctx.role().peer(Direction::Right));
        let right_receiver = ctx.recv_channel::<F>(ctx.role().peer(Direction::Right));

        // Send share to helpers to the right and left
        // send except to left_out
        if ctx.role().peer(Direction::Left) != left_out {
            left_sender.send(record_id, right).await?;
        }
        if ctx.role().peer(Direction::Right) != left_out {
            right_sender.send(record_id, left).await?;
        }
        if ctx.role() == left_out {
            Ok(None)
        } else {
            let (share_from_left, share_from_right) = try_join(
                left_receiver.receive(record_id),
                right_receiver.receive(record_id),
            )
            .await?;

            if share_from_left == share_from_right {
                Ok(Some((left + right + share_from_left).into_array()))
            } else {
                Err(Error::MaliciousRevealFailed)
            }
        }
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::iter::zip;

    use futures::future::{join_all, try_join, try_join3};

    use crate::{
        error::Error,
        ff::{Field, Fp31, Fp32BitPrime},
        helpers::{Direction, Role},
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
            IntoShares, SharedValue,
        },
        test_fixture::{join3v, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn simple() -> Result<(), Error> {
        type TestField = Fp31;

        let mut rng = thread_rng();
        let world = TestWorld::default();

        let input = rng.gen::<TestField>();
        let results = world
            .semi_honest(input, |ctx, share| async move {
                TestField::from_array(
                    &share
                        .reveal(ctx.set_total_records(1), RecordId::from(0))
                        .await
                        .unwrap(),
                )
            })
            .await;

        assert_eq!(input, results[0]);
        assert_eq!(input, results[1]);
        assert_eq!(input, results[2]);

        Ok(())
    }

    #[tokio::test]
    pub async fn partial() -> Result<(), Error> {
        type TestField = Fp31;

        let mut rng = thread_rng();
        let world = TestWorld::default();

        for &left_out in Role::all() {
            let input = rng.gen::<TestField>();
            let results = world
                .semi_honest(input, |ctx, share| async move {
                    share
                        .partial_reveal(ctx.set_total_records(1), RecordId::from(0), left_out)
                        .await
                        .unwrap()
                        .map(|revealed| TestField::from_array(&revealed))
                })
                .await;

            for &helper in Role::all() {
                if helper == left_out {
                    assert_eq!(None, results[helper]);
                } else {
                    assert_eq!(Some(input), results[helper]);
                }
            }
        }

        Ok(())
    }

    #[tokio::test]
    pub async fn vectorized() -> Result<(), Error> {
        type TestField = [Fp32BitPrime; 32];

        let mut rng = thread_rng();
        let world = TestWorld::default();

        let input = rng.gen::<TestField>();
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
        type TestField = Fp31;

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
        let input: TestField = rng.gen();

        let m_shares = join3v(
            zip(m_ctx.iter(), input.share_with(&mut rng))
                .map(|(m_ctx, share)| async { m_ctx.upgrade(share).await }),
        )
        .await;

        let results = join_all(zip(m_ctx.clone().into_iter(), m_shares).map(
            |(m_ctx, m_share)| async move {
                TestField::from_array(&m_share.reveal(m_ctx, record_id).await.unwrap())
            },
        ))
        .await;

        assert_eq!(input, results[0]);
        assert_eq!(input, results[1]);
        assert_eq!(input, results[2]);

        Ok(())
    }

    #[tokio::test]
    pub async fn malicious_partial() -> Result<(), Error> {
        type TestField = Fp31;

        let mut rng = thread_rng();
        let world = TestWorld::default();

        for &left_out in Role::all() {
            let sh_ctx = world.malicious_contexts();
            let v = sh_ctx.map(UpgradableContext::validator);
            let m_ctx: [_; 3] = v
                .iter()
                .map(|v| v.context().set_total_records(1))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            let record_id = RecordId::from(0);
            let input: TestField = rng.gen();

            let m_shares = join3v(
                zip(m_ctx.iter(), input.share_with(&mut rng))
                    .map(|(m_ctx, share)| async { m_ctx.upgrade(share).await }),
            )
            .await;

            let results = join_all(zip(m_ctx.clone().into_iter(), m_shares).map(
                |(m_ctx, m_share)| async move {
                    m_share
                        .partial_reveal(m_ctx, record_id, left_out)
                        .await
                        .unwrap()
                },
            ))
            .await;

            for &helper in Role::all() {
                if helper == left_out {
                    assert_eq!(None, results[helper]);
                } else {
                    assert_eq!(Some(input.into_array()), results[helper]);
                }
            }
        }

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
            reveal_with_additive_attack(
                m_ctx[2].clone(),
                record_id,
                &m_shares[2],
                false,
                Fp31::ONE,
            ),
        )
        .await;

        assert!(matches!(result, Err(Error::MaliciousRevealFailed)));

        Ok(())
    }

    #[tokio::test]
    pub async fn malicious_partial_validation_fail() -> Result<(), Error> {
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
            m_shares[0].partial_reveal(m_ctx[0].clone(), record_id, Role::H3),
            m_shares[1].partial_reveal(m_ctx[1].clone(), record_id, Role::H3),
            reveal_with_additive_attack(m_ctx[2].clone(), record_id, &m_shares[2], true, Fp31::ONE),
        )
        .await;

        assert!(matches!(result, Err(Error::MaliciousRevealFailed)));

        Ok(())
    }

    pub async fn reveal_with_additive_attack<F: ExtendableField>(
        ctx: UpgradedMaliciousContext<'_, F>,
        record_id: RecordId,
        input: &MaliciousReplicated<F>,
        left_out: bool,
        additive_error: F,
    ) -> Result<Option<F>, Error> {
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

        if left_out {
            Ok(None)
        } else {
            let (share_from_left, _share_from_right): (F, F) =
                try_join(left_recv.receive(record_id), right_recv.receive(record_id)).await?;

            Ok(Some(left + right + share_from_left))
        }
    }
}
