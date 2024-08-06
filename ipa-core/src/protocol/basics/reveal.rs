use std::{
    future::Future,
    iter::{repeat, zip},
};

use embed_doc_image::embed_doc_image;
use futures::{FutureExt, TryFutureExt};
use ipa_step::{Step, StepNarrow};

use crate::{
    error::Error,
    ff::boolean::Boolean,
    helpers::{Direction, MaybeFuture, Role},
    protocol::{
        boolean::step::TwoHundredFiftySixBitOpStep,
        context::{
            dzkp_validator::DZKPValidator, Context, DZKPUpgradedMaliciousContext,
            DZKPUpgradedSemiHonestContext, UpgradedMaliciousContext, UpgradedSemiHonestContext,
        },
        Gate, RecordId,
    },
    secret_sharing::{
        replicated::{
            malicious::{AdditiveShare as MaliciousReplicated, ExtendableField},
            semi_honest::AdditiveShare as Replicated,
        },
        BitDecomposed, SharedValue, Vectorizable,
    },
    sharding::ShardBinding,
};

/// Trait for reveal protocol to open a shared secret to all helpers inside the MPC ring.
pub trait Reveal<C: Context> {
    type Output: Send + Sync + 'static;
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

impl<C, S> Reveal<C> for BitDecomposed<S>
where
    C: Context,
    S: Reveal<C> + Send + Sync + 'static,
{
    type Output = Vec<<S as Reveal<C>>::Output>;

    fn generic_reveal<'fut>(
        &'fut self,
        ctx: C,
        record_id: RecordId,
        excluded: Option<Role>,
    ) -> impl Future<Output = Result<Option<Self::Output>, Error>> + Send + 'fut
    where
        C: 'fut,
    {
        ctx.parallel_join(zip(&**self, repeat(ctx.clone())).enumerate().map(
            |(i, (bit, ctx))| async move {
                generic_reveal(
                    ctx.narrow(&TwoHundredFiftySixBitOpStep::Bit(i)),
                    record_id,
                    excluded,
                    bit,
                )
                .await
            },
        ))
        .map(move |res| {
            res.map(move |vec| {
                match vec.first() {
                    None => (excluded != Some(ctx.role())).then(Vec::new),
                    Some(&None) => None,
                    Some(&Some(_)) => Some(
                        // Transform `Vec<Option<V>>` to `Option<Vec<V>>`.
                        vec.into_iter()
                            .map(|opt_v| {
                                opt_v.expect("inconsistent full vs. partial reveal behavior")
                            })
                            .collect::<Vec<_>>(),
                    ),
                }
            })
        })
    }
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
pub async fn semi_honest_reveal<'fut, C, V, const N: usize>(
    ctx: C,
    record_id: RecordId,
    excluded: Option<Role>,
    share: &'fut Replicated<V, N>,
) -> Result<Option<<V as Vectorizable<N>>::Array>, Error>
where
    C: Context + 'fut,
    V: SharedValue + Vectorizable<N>,
{
    let left = share.left_arr();
    let right = share.right_arr();

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

impl<'a, B, V, const N: usize> Reveal<UpgradedSemiHonestContext<'a, B, V>> for Replicated<V, N>
where
    B: ShardBinding,
    V: SharedValue + Vectorizable<N> + ExtendableField,
{
    type Output = <V as Vectorizable<N>>::Array;

    async fn generic_reveal<'fut>(
        &'fut self,
        ctx: UpgradedSemiHonestContext<'a, B, V>,
        record_id: RecordId,
        excluded: Option<Role>,
    ) -> Result<Option<Self::Output>, Error>
    where
        UpgradedSemiHonestContext<'a, B, V>: 'fut,
    {
        semi_honest_reveal(ctx, record_id, excluded, self).await
    }
}

impl<'a, B, const N: usize> Reveal<DZKPUpgradedSemiHonestContext<'a, B>> for Replicated<Boolean, N>
where
    B: ShardBinding,
    Boolean: Vectorizable<N>,
{
    type Output = <Boolean as Vectorizable<N>>::Array;

    async fn generic_reveal<'fut>(
        &'fut self,
        ctx: DZKPUpgradedSemiHonestContext<'a, B>,
        record_id: RecordId,
        excluded: Option<Role>,
    ) -> Result<Option<Self::Output>, Error>
    where
        DZKPUpgradedSemiHonestContext<'a, B>: 'fut,
    {
        semi_honest_reveal(ctx, record_id, excluded, self).await
    }
}

/// This implements the malicious reveal protocol over replicated secret sharings.
/// It works similarly to semi-honest reveal, the key difference is that each helper sends its share
/// to both helpers (right and left) and upon receiving 2 shares from peers it validates that they
/// indeed match.
pub async fn malicious_reveal<'fut, C, V, const N: usize>(
    ctx: C,
    record_id: RecordId,
    excluded: Option<Role>,
    share: &'fut Replicated<V, N>,
) -> Result<Option<<V as Vectorizable<N>>::Array>, Error>
where
    C: Context + 'fut,
    V: SharedValue + Vectorizable<N>,
{
    use futures::future::try_join;

    let left = share.left_arr();
    let right = share.right_arr();
    let left_sender =
        ctx.send_channel::<<V as Vectorizable<N>>::Array>(ctx.role().peer(Direction::Left));
    let left_receiver =
        ctx.recv_channel::<<V as Vectorizable<N>>::Array>(ctx.role().peer(Direction::Left));
    let right_sender =
        ctx.send_channel::<<V as Vectorizable<N>>::Array>(ctx.role().peer(Direction::Right));
    let right_receiver =
        ctx.recv_channel::<<V as Vectorizable<N>>::Array>(ctx.role().peer(Direction::Right));

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
            Ok(Some(share_from_left + left + right))
        } else {
            Err(Error::MaliciousRevealFailed)
        }
    }
}

impl<'a, F> Reveal<UpgradedMaliciousContext<'a, F>> for Replicated<F>
where
    F: ExtendableField,
{
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
        malicious_reveal(ctx, record_id, excluded, self).await
    }
}

impl<'a, F> Reveal<UpgradedMaliciousContext<'a, F>> for MaliciousReplicated<F>
where
    F: ExtendableField,
{
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
        use crate::secret_sharing::replicated::malicious::ThisCodeIsAuthorizedToDowngradeFromMalicious;

        let x_share = self.x().access_without_downgrade();
        malicious_reveal(ctx, record_id, excluded, x_share).await
    }
}

impl<'a, const N: usize> Reveal<DZKPUpgradedMaliciousContext<'a>> for Replicated<Boolean, N>
where
    Boolean: Vectorizable<N>,
{
    type Output = <Boolean as Vectorizable<N>>::Array;

    async fn generic_reveal<'fut>(
        &'fut self,
        ctx: DZKPUpgradedMaliciousContext<'a>,
        record_id: RecordId,
        excluded: Option<Role>,
    ) -> Result<Option<Self::Output>, Error>
    where
        DZKPUpgradedMaliciousContext<'a>: 'fut,
    {
        malicious_reveal(ctx, record_id, excluded, self).await
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
    S: Reveal<C> + ?Sized,
{
    S::reveal(v, ctx, record_id)
}

pub fn partial_reveal<'fut, C, S>(
    ctx: C,
    record_id: RecordId,
    excluded: Role,
    v: &'fut S,
) -> impl Future<Output = Result<Option<S::Output>, Error>> + Send + 'fut
where
    C: Context + 'fut,
    S: Reveal<C> + ?Sized,
{
    S::partial_reveal(v, ctx, record_id, excluded)
}

pub fn generic_reveal<'fut, C, S>(
    ctx: C,
    record_id: RecordId,
    excluded: Option<Role>,
    v: &'fut S,
) -> impl Future<Output = Result<Option<S::Output>, Error>> + Send + 'fut
where
    C: Context + 'fut,
    S: Reveal<C> + ?Sized,
{
    S::generic_reveal(v, ctx, record_id, excluded)
}

pub async fn validated_partial_reveal<'fut, V, S, STEP>(
    validator: V,
    step: &'fut STEP,
    record_id: RecordId,
    excluded: Role,
    v: &'fut S,
) -> Result<Option<<S as Reveal<V::Context>>::Output>, Error>
where
    V: DZKPValidator + 'fut,
    S: Reveal<V::Context> + Send + Sync + ?Sized,
    STEP: Step + Send + Sync + 'static,
    Gate: StepNarrow<STEP>,
{
    let ctx = validator.context().narrow(step);
    validator.validate_record(record_id).await?;
    partial_reveal(ctx, record_id, excluded, v).await
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::iter::{self, zip};

    use futures::future::join_all;

    use crate::{
        error::Error,
        ff::{boolean::Boolean, Field, Fp31, Fp32BitPrime},
        helpers::{
            in_memory_config::{MaliciousHelper, MaliciousHelperContext},
            Role,
        },
        protocol::{
            basics::{partial_reveal, reveal, Reveal},
            context::{upgrade::Upgradable, Context, UpgradableContext, Validator},
            RecordId,
        },
        rand::{thread_rng, Rng},
        secret_sharing::{
            replicated::semi_honest::AdditiveShare, BitDecomposed, IntoShares, SecretSharing,
            SharedValue, Vectorizable,
        },
        test_executor::run,
        test_fixture::{join3v, Runner, TestWorld, TestWorldConfig},
    };

    #[tokio::test]
    pub async fn simple() -> Result<(), Error> {
        type TestField = Fp31;

        let mut rng = thread_rng();
        let world = TestWorld::default();

        let input = rng.gen::<TestField>();
        let results = world
            .upgraded_semi_honest(input, |ctx, share| async move {
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
                .upgraded_semi_honest(input, |ctx, share| async move {
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
            .upgraded_semi_honest(
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
            zip(m_ctx.iter(), input.share_with(&mut rng)).map(|(m_ctx, share)| async {
                share.upgrade(RecordId::FIRST, m_ctx.clone()).await
            }),
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

            let m_shares = join3v(zip(m_ctx.iter(), input.share_with(&mut rng)).map(
                |(m_ctx, share)| async { share.upgrade(RecordId::FIRST, m_ctx.clone()).await },
            ))
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

    const MALICIOUS_REVEAL_STEP: &str = "malicious-reveal";

    async fn do_malicious_reveal<'ctx, C, F, S>(ctx: C, partial: bool, share: S)
    where
        C: Context + 'ctx,
        F: Field,
        S: SecretSharing<F> + Reveal<C, Output = <F as Vectorizable<1>>::Array>,
    {
        let ctx = ctx.set_total_records(1);
        let my_role = ctx.role();
        let ctx = ctx.narrow(MALICIOUS_REVEAL_STEP);

        let r = if partial {
            partial_reveal(ctx, RecordId::FIRST, Role::H3, &share).await
        } else {
            reveal(ctx, RecordId::FIRST, &share).await.map(Some)
        };

        // H1 should be able to see the mismatch
        if my_role == Role::H1 {
            assert!(matches!(r, Err(Error::MaliciousRevealFailed)));
        } else {
            // sanity check
            r.unwrap();
        }
    }

    #[allow(clippy::ptr_arg)] // to match StreamInterceptor trait
    fn interceptor<F: Field>(ctx: &MaliciousHelperContext, data: &mut Vec<u8>) {
        // H3 runs an additive attack against H1 (on the right) by
        // adding a 1 to the left part of share it is holding
        if ctx.gate.as_ref().contains(MALICIOUS_REVEAL_STEP) && ctx.dest == Role::H1 {
            let v = F::deserialize_from_slice(data) + F::ONE;
            v.serialize_to_slice(data);
        }
    }

    #[test]
    pub fn malicious_generic_validation_fail() {
        run(move || async move {
            let partial = false;
            let mut rng = thread_rng();
            let mut config = TestWorldConfig::default();
            config.stream_interceptor =
                MaliciousHelper::new(Role::H3, config.role_assignment(), interceptor::<Fp31>);

            let world = TestWorld::new_with(config);
            let input: Fp31 = rng.gen();
            world
                .upgraded_malicious(input, |ctx, share| do_malicious_reveal(ctx, partial, share))
                .await;
        });
    }

    #[test]
    pub fn malicious_partial_validation_fail() {
        run(move || async move {
            let partial = true;
            let mut rng = thread_rng();
            let mut config = TestWorldConfig::default();
            config.stream_interceptor =
                MaliciousHelper::new(Role::H3, config.role_assignment(), interceptor::<Fp31>);

            let world = TestWorld::new_with(config);
            let input: Fp31 = rng.gen();
            world
                .upgraded_malicious(input, |ctx, share| do_malicious_reveal(ctx, partial, share))
                .await;
        });
    }

    #[test]
    pub fn dzkp_malicious_generic_validation_fail() {
        run(move || async move {
            let partial = false;
            let mut rng = thread_rng();
            let mut config = TestWorldConfig::default();
            config.stream_interceptor =
                MaliciousHelper::new(Role::H3, config.role_assignment(), interceptor::<Boolean>);

            let world = TestWorld::new_with(config);
            let input: Boolean = rng.gen();
            world
                .dzkp_malicious(input, |ctx, share| do_malicious_reveal(ctx, partial, share))
                .await;
        });
    }

    #[test]
    pub fn dzkp_malicious_partial_validation_fail() {
        run(move || async move {
            let partial = true;
            let mut rng = thread_rng();
            let mut config = TestWorldConfig::default();
            config.stream_interceptor =
                MaliciousHelper::new(Role::H3, config.role_assignment(), interceptor::<Boolean>);

            let world = TestWorld::new_with(config);
            let input: Boolean = rng.gen();
            world
                .dzkp_malicious(input, |ctx, share| do_malicious_reveal(ctx, partial, share))
                .await;
        });
    }

    #[tokio::test]
    async fn reveal_empty_vec() {
        let [res0, res1, res2] = TestWorld::default()
            .upgraded_semi_honest(iter::empty::<Boolean>(), |ctx, share| async move {
                reveal(ctx, RecordId::FIRST, &BitDecomposed::new(share))
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|v| Boolean::from_array(&v))
                    .collect::<Vec<_>>()
            })
            .await;

        assert_eq!(res0, vec![]);
        assert_eq!(res1, vec![]);
        assert_eq!(res2, vec![]);
    }

    #[tokio::test]
    async fn reveal_empty_vec_partial() {
        let [res0, res1, res2] = TestWorld::default()
            .upgraded_semi_honest(iter::empty::<Boolean>(), |ctx, share| async move {
                partial_reveal(ctx, RecordId::FIRST, Role::H3, &BitDecomposed::new(share))
                    .await
                    .unwrap()
            })
            .await;

        assert_eq!(res0, Some(vec![]));
        assert_eq!(res1, Some(vec![]));
        assert_eq!(res2, None);
    }
}
