use std::future::Future;

use embed_doc_image::embed_doc_image;
use futures::TryFutureExt;

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
    helpers::MaybeFuture,
    protocol::context::UpgradedMaliciousContext,
    secret_sharing::replicated::malicious::{
        AdditiveShare as MaliciousReplicated, ExtendableField,
    },
};

/// Trait for reveal protocol to open a shared secret to all helpers inside the MPC ring.
pub trait Reveal<C: Context, const N: usize>: Sized {
    type Output;
    /// Reveal a shared secret to all helpers in the MPC ring.
    ///
    /// Note that after method is called, it must be assumed that the secret value has been
    /// revealed to at least one of the helpers.  Even in case when method never terminates,
    /// returns an error, etc.
    fn reveal<'fut>(
        &'fut self,
        ctx: C,
        record_id: RecordId,
    ) -> impl Future<Output = Result<Self::Output, Error>> + Send + 'fut
    where
        C: 'fut,
    {
        // Passing `excluded = None` guarantees any ok result is `Some`.
        self.generic_reveal(ctx, record_id, None)
            .map_ok(Option::unwrap)
    }

    /// Partial reveal protocol to open a shared secret to all helpers except helper `excluded` inside the MPC ring.
    fn partial_reveal<'fut>(
        &'fut self,
        ctx: C,
        record_id: RecordId,
        excluded: Role,
    ) -> impl Future<Output = Result<Option<Self::Output>, Error>> + Send + 'fut
    where
        C: 'fut,
    {
        self.generic_reveal(ctx, record_id, Some(excluded))
    }

    /// Generic reveal implementation usable for both `reveal` and `partial_reveal`.
    ///
    /// When `excluded` is `None`, open a shared secret to all helpers in the MPC ring.
    /// When `excluded` is `Some`, open a shared secret to all helpers except the helper
    /// specified in `excluded`.
    fn generic_reveal<'fut>(
        &'fut self,
        ctx: C,
        record_id: RecordId,
        excluded: Option<Role>,
    ) -> impl Future<Output = Result<Option<Self::Output>, Error>> + Send + 'fut
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
#[embed_doc_image("reveal", "images/reveal.png")]
impl<C: Context, V: SharedValue + Vectorizable<N>, const N: usize> Reveal<C, N>
    for Replicated<V, N>
{
    type Output = <V as Vectorizable<N>>::Array;

    async fn generic_reveal<'fut>(
        &'fut self,
        ctx: C,
        record_id: RecordId,
        excluded: Option<Role>,
    ) -> Result<Option<<V as Vectorizable<N>>::Array>, Error>
    where
        C: 'fut,
    {
        let left = self.left_arr();
        let right = self.right_arr();

        // Send shares, unless the target helper is excluded
        if Some(ctx.role().peer(Direction::Right)) != excluded {
            ctx.send_channel::<<V as Vectorizable<N>>::Array>(ctx.role().peer(Direction::Right))
                .send(record_id, left)
                .await?;
        }

        if Some(ctx.role()) == excluded {
            Ok(None)
        } else {
            // Sleep until `helper's left` sends their share
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
impl<'a, F: ExtendableField> Reveal<UpgradedMaliciousContext<'a, F>, 1> for MaliciousReplicated<F> {
    type Output = <F as Vectorizable<1>>::Array;

    async fn generic_reveal<'fut>(
        &'fut self,
        ctx: UpgradedMaliciousContext<'a, F>,
        record_id: RecordId,
        excluded: Option<Role>,
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

        // Send shares to the left and right helpers, unless excluded.
        let send_left_fut =
            MaybeFuture::future_or_ok(Some(ctx.role().peer(Direction::Left)) != excluded, || {
                left_sender.send(record_id, right)
            });

        let send_right_fut =
            MaybeFuture::future_or_ok(Some(ctx.role().peer(Direction::Right)) != excluded, || {
                right_sender.send(record_id, left)
            });
        try_join(send_left_fut, send_right_fut).await?;

        if Some(ctx.role()) == excluded {
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

// Workaround for https://github.com/rust-lang/rust/issues/100013. Calling these wrapper functions
// instead of the trait methods seems to hide the `impl Future` GAT.

pub fn reveal<'fut, C, S>(
    ctx: C,
    record_id: RecordId,
    v: &'fut S,
) -> impl Future<Output = Result<S::Output, Error>> + Send + 'fut
where
    C: Context + 'fut,
    S: Reveal<C, 1>,
{
    S::reveal(v, ctx, record_id)
}

pub fn partial_reveal<'fut, C, S, const N: usize>(
    ctx: C,
    record_id: RecordId,
    excluded: Role,
    v: &'fut S,
) -> impl Future<Output = Result<Option<S::Output>, Error>> + Send + 'fut
where
    C: Context + 'fut,
    S: Reveal<C, N>,
{
    S::partial_reveal(v, ctx, record_id, excluded)
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
            replicated::{
                malicious::{
                    AdditiveShare as MaliciousReplicated, ExtendableField,
                    ThisCodeIsAuthorizedToDowngradeFromMalicious,
                },
                semi_honest::AdditiveShare,
            },
            IntoShares, SharedValue,
        },
        test_executor::run,
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

        for &excluded in Role::all() {
            let input = rng.gen::<TestField>();
            let results = world
                .semi_honest(input, |ctx, share| async move {
                    share
                        .partial_reveal(ctx.set_total_records(1), RecordId::from(0), excluded)
                        .await
                        .unwrap()
                        .map(|revealed| TestField::from_array(&revealed))
                })
                .await;

            for &helper in Role::all() {
                if helper == excluded {
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
            .semi_honest(
                input,
                |ctx, share: AdditiveShare<Fp32BitPrime, 32>| async move {
                    share
                        .reveal(ctx.set_total_records(1), RecordId::from(0))
                        .await
                        .unwrap()
                },
            )
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
        let m_ctx = v.each_ref().map(|v| v.context().set_total_records(1));

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

        for &excluded in Role::all() {
            let sh_ctx = world.malicious_contexts();
            let v = sh_ctx.map(UpgradableContext::validator);
            let m_ctx = v.each_ref().map(|v| v.context().set_total_records(1));

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
                        .partial_reveal(m_ctx, record_id, excluded)
                        .await
                        .unwrap()
                },
            ))
            .await;

            for &helper in Role::all() {
                if helper == excluded {
                    assert_eq!(None, results[helper]);
                } else {
                    assert_eq!(Some(input.into_array()), results[helper]);
                }
            }
        }

        Ok(())
    }

    #[test]
    pub fn malicious_validation_fail() {
        run(|| async {
            let mut rng = thread_rng();
            let world = TestWorld::default();
            let sh_ctx = world.malicious_contexts();
            let v = sh_ctx.map(UpgradableContext::validator);
            let m_ctx = v.each_ref().map(|v| v.context().set_total_records(1));

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
        });
    }

    #[test]
    pub fn malicious_partial_validation_fail() {
        run(|| async {
            let mut rng = thread_rng();
            let world = TestWorld::default();
            let sh_ctx = world.malicious_contexts();
            let v = sh_ctx.map(UpgradableContext::validator);
            let m_ctx: [_; 3] = v.each_ref().map(|v| v.context().set_total_records(1));

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
                reveal_with_additive_attack(
                    m_ctx[2].clone(),
                    record_id,
                    &m_shares[2],
                    true,
                    Fp31::ONE,
                ),
            )
            .await;

            assert!(matches!(result, Err(Error::MaliciousRevealFailed)));
        });
    }

    pub async fn reveal_with_additive_attack<F: ExtendableField>(
        ctx: UpgradedMaliciousContext<'_, F>,
        record_id: RecordId,
        input: &MaliciousReplicated<F>,
        excluded: bool,
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

        if excluded {
            Ok(None)
        } else {
            let (share_from_left, _share_from_right): (F, F) =
                try_join(left_recv.receive(record_id), right_recv.receive(record_id)).await?;

            Ok(Some(left + right + share_from_left))
        }
    }
}
