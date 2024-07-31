use crate::{
    error::Error,
    ff::Field,
    protocol::{
        basics::{malicious_reveal, mul::semi_honest_multiply, step::CheckZeroStep as Step},
        context::Context,
        prss::{FromRandom, SharedRandomness},
        RecordId,
    },
    secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
};

#[cfg(test)]
static SH1: once_cell::sync::Lazy<tests::NotifyOnceCell<crate::ff::Fp32BitPrime>> =
    once_cell::sync::Lazy::new(|| tests::NotifyOnceCell::new());

/// A very simple protocol to check if a replicated secret sharing is a sharing of zero.
///
/// NOTE: this protocol leaks information about `v` the helpers. Please only use this in cases where
/// this type of information leakage is acceptable, such as where `v` is the product of a secret value
/// and a random, unknown value.
///
/// This is an implementation of PROTOCOL 3.7 from the paper:
/// Fast Large-Scale Honest-Majority MPC for Malicious Adversaries
/// <https://link.springer.com/content/pdf/10.1007/978-3-319-96878-0_2.pdf>
///
/// The parties start out holding a replicated secret sharing of a value `v`, which they would like to check for equality to zero.
/// First, the parties generate a secret sharing of a random value `r`, which is not known to any of them.
/// Next, the parties compute a secret sharing of `r * v` using a multiplication protocol that is secure up to an additive attack.
/// Then, the parties reveal (sometimes called "open") the secret sharing of `r * v`
/// If `v` was a secret sharing of zero, this revealed value will also be zero.
/// On the other hand, if `v` was NOT a secret sharing of zero, then there are two possibilities:
/// 1.) If the randomly chosen value `r` just so happenned to be zero, then the revealed value will be zero.
/// This will happen with probability `1/|F|` (where `|F|` denotes the cardinality of the field)
/// 2.) If the randomly chosen value `r` is any other value in the field aside from zero, then the revealed value will NOT be zero.
///
/// Clearly, the accuracy of this protocol is highly dependent on the field that is used.
/// In a large field, like the integers modulo 2^31 - 1, the odds of `check_zero` returning "true"
/// when `v` is NOT actually a sharing of zero is extrmely small; it is less than one two billion odds.
/// In a silly field, like our test field of the integers modulo 31, the odds are very good. It'll incorrectly return "true"
/// about 3.2% of the time.
///
/// ## Errors
/// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
/// back via the error response
/// ## Panics
/// If the full reveal of `rv_share` does not return a value, which would only happen if the
/// reveal implementation is broken.
pub async fn check_zero<C, F>(ctx: C, record_id: RecordId, v: &Replicated<F>) -> Result<bool, Error>
where
    C: Context,
    F: Field + FromRandom,
{
    let r_sharing: Replicated<F> = ctx.prss().generate(record_id);

    let rv_share =
        semi_honest_multiply(ctx.narrow(&Step::MultiplyWithR), record_id, &r_sharing, v).await?;
    tracing::info!("{:?}", &rv_share);
    let rv = F::from_array(
        &malicious_reveal(ctx.narrow(&Step::RevealR), record_id, None, &rv_share)
            .await?
            .expect("full reveal should always return a value"),
    );

    tracing::info!("{:?}", &rv);
    Ok(rv == F::ZERO)
}

#[cfg(test)]
pub async fn check_zero_fp32bitprime<C>(
    ctx: C,
    record_id: RecordId,
    v: &Replicated<crate::ff::Fp32BitPrime>,
) -> Result<bool, Error>
where
    C: Context,
{
    use crate::{
        ff::Fp32BitPrime,
        secret_sharing::{replicated::ReplicatedSecretSharing, SharedValue},
    };

    let r_sharing: Replicated<Fp32BitPrime> = ctx.prss().generate(record_id);

    let rv_share =
        semi_honest_multiply(ctx.narrow(&Step::MultiplyWithR), record_id, &r_sharing, v).await?;
    tracing::info!("{:?}", &rv_share);
    if ctx.role() == crate::helpers::Role::H1 {
        SH1.set(rv_share.right()).unwrap();
        tracing::info!("sent sh1 = {:?}", rv_share.right());
    }
    let rv = Fp32BitPrime::from_array(
        &malicious_reveal(ctx.narrow(&Step::RevealR), record_id, None, &rv_share)
            .await?
            .expect("full reveal should always return a value"),
    );

    Ok(rv == Fp32BitPrime::ZERO)
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::{
        future::ready,
        pin::Pin,
        sync::{Arc, Mutex},
    };

    use futures::{
        future::{join, try_join3},
        Future, FutureExt,
    };
    use generic_array::GenericArray;
    use once_cell::sync::OnceCell;
    use rand::Rng;
    use tokio::sync::Notify;
    use typenum::U4;

    use crate::{
        error::Error,
        ff::{Fp31, Fp32BitPrime, PrimeField, Serializable, U128Conversions},
        helpers::{
            in_memory_config::{InspectContext, StreamInterceptor},
            HelperIdentity, TransportIdentity,
        },
        protocol::{
            basics::check_zero::{check_zero, check_zero_fp32bitprime},
            context::Context,
            RecordId,
        },
        rand::thread_rng,
        secret_sharing::{IntoShares, SharedValue},
        test_fixture::{Runner, TestWorld, TestWorldConfig},
    };

    #[tokio::test]
    async fn basic() -> Result<(), Error> {
        let world = TestWorld::default();
        let context = world.contexts().map(|ctx| ctx.set_total_records(1));
        let mut rng = thread_rng();
        let mut counter = 0_u32;

        for v in 0..u32::from(Fp31::PRIME) {
            let v = Fp31::truncate_from(v);
            let mut num_false_positives = 0;
            for _ in 0..10 {
                let v_shares = v.share_with(&mut rng);
                let record_id = RecordId::from(0_u32);
                let iteration = format!("{counter}");
                counter += 1;

                let protocol_output = try_join3(
                    check_zero(context[0].narrow(&iteration), record_id, &v_shares[0]),
                    check_zero(context[1].narrow(&iteration), record_id, &v_shares[1]),
                    check_zero(context[2].narrow(&iteration), record_id, &v_shares[2]),
                )
                .await?;

                // All three helpers should always get the same result
                assert_eq!(protocol_output.0, protocol_output.1);
                assert_eq!(protocol_output.1, protocol_output.2);

                if v == Fp31::ZERO {
                    // When it actually is a secret sharing of zero
                    // the helpers should definitely all receive "true"
                    assert!(protocol_output.0);
                    assert!(protocol_output.1);
                    assert!(protocol_output.2);
                } else if protocol_output.0 {
                    // Unfortunately, there is a small chance of an incorrect
                    // "true", even in when the secret shared value is NOT zero.
                    // Since we will test out 10 different random secret sharings
                    // let's count how many false positives we get. Odds are there
                    // will be 0, 1, or maybe 2 out of 10
                    if protocol_output.0 {
                        num_false_positives += 1;
                    }
                }
            }

            // Fp31 is just too small of a field.
            // Through random chance, it'll incorrectly return "true"
            // one time in 31. The odds of incorrectly returning "true"
            // 5 times or more is... small...
            assert!(num_false_positives < 5);
        }

        Ok(())
    }

    pub struct NotifyOnceCell<T: Clone + Send + Sync> {
        inner: Mutex<NotifyOnceCellInner<T>>,
    }

    struct NotifyOnceCellInner<T: Clone + Send + Sync> {
        cell: OnceCell<T>,
        notify: Arc<Notify>,
    }

    impl<T: Clone + Send + Sync> NotifyOnceCell<T> {
        pub fn new() -> Self {
            Self {
                inner: Mutex::new(NotifyOnceCellInner {
                    cell: OnceCell::new(),
                    notify: Arc::new(Notify::new()),
                }),
            }
        }

        pub fn set(&self, value: T) -> Result<(), T> {
            let inner = self.inner.lock().unwrap();
            inner.cell.set(value)?;
            inner.notify.notify_waiters();
            Ok(())
        }

        pub fn get(&self) -> Pin<Box<dyn Future<Output = T> + Send + '_>> {
            let inner = self.inner.lock().unwrap();
            if let Some(value) = inner.cell.get() {
                return ready(value.clone()).boxed();
            }
            let notify = inner.notify.clone();
            async move {
                notify.notified().await;
                self.inner.lock().unwrap().cell.get().unwrap().clone()
            }
            .boxed()
        }
    }

    struct MaliciousCheckZeroInterceptor {
        sh2: NotifyOnceCell<Fp32BitPrime>,
    }

    impl MaliciousCheckZeroInterceptor {
        fn new() -> Self {
            Self {
                sh2: NotifyOnceCell::new(),
            }
        }
    }

    impl StreamInterceptor for MaliciousCheckZeroInterceptor {
        type Context = InspectContext;

        fn peek<'a>(
            &'a self,
            ctx: &'a Self::Context,
            data: &'a mut Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            if ctx
                .gate
                .as_ref()
                .contains(super::Step::MultiplyWithR.as_ref())
                && ctx.identity == HelperIdentity::ONE
                || ctx.gate.as_ref().contains(super::Step::RevealR.as_ref())
                    && ctx.identity == HelperIdentity::ONE
                    && ctx.dest == HelperIdentity::TWO.as_str()
            {
                async {
                    assert_eq!(data.len(), 4);
                    let (sh1, sh2) = join(super::SH1.get(), self.sh2.get()).await;
                    tracing::info!("got shares: {sh1:?} {sh2:?}");
                    let adjusted_share = -sh1 - sh2;
                    tracing::info!("adjusted share {adjusted_share:?}");
                    adjusted_share.serialize(
                        <&mut GenericArray<u8, U4>>::try_from(data.as_mut_slice()).unwrap(),
                    );
                }
                .boxed()
            } else if ctx.gate.as_ref().contains(super::Step::RevealR.as_ref())
                && ctx.identity == HelperIdentity::TWO
                && ctx.dest == HelperIdentity::ONE.as_str()
            {
                assert_eq!(data.len(), 4);
                let sh2 = Fp32BitPrime::deserialize_unchecked(
                    <&GenericArray<u8, U4>>::try_from(data.as_slice()).unwrap(),
                );
                self.sh2.set(sh2).unwrap();
                tracing::info!("sent sh2 = {sh2:?}");
                ready(()).boxed()
            } else {
                ready(()).boxed()
            }
        }
    }

    #[tokio::test]
    async fn malicious_check_zero() {
        let mut config = TestWorldConfig::default();
        config.stream_interceptor = Arc::new(MaliciousCheckZeroInterceptor::new());
        let world = TestWorld::new_with(&config);
        let mut rng = thread_rng();
        let v = rng.gen::<Fp32BitPrime>();

        let [res0, res1, res2] = world
            .semi_honest(v, |ctx, v| async move {
                check_zero_fp32bitprime(ctx.set_total_records(1), RecordId::FIRST, &v)
                    .await
                    .unwrap()
            })
            .await;

        assert_eq!(res0, false, "zero check failed on H1");
        assert_eq!(res1, false, "zero check failed on H2");
        assert_eq!(res2, false, "zero check failed on H3");
    }
}
