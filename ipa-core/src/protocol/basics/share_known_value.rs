use crate::{
    helpers::Role,
    protocol::context::Context,
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing},
        SharedValue,
    },
};
#[cfg(feature = "descriptive-gate")]
use crate::{
    protocol::context::UpgradedContext,
    protocol::context::UpgradedMaliciousContext,
    secret_sharing::replicated::malicious::{
        AdditiveShare as MaliciousReplicated, ExtendableField,
    },
};

/// Produce a share of some pre-determined constant.
///
/// The context is only used to determine the helper role. It is not used for communication or PRSS,
/// and it is not necessary to use a uniquely narrowed context.
pub trait ShareKnownValue<C: Context, V: SharedValue> {
    fn share_known_value(ctx: &C, value: V) -> Self;
}

impl<C: Context, V: SharedValue> ShareKnownValue<C, V> for Replicated<V> {
    fn share_known_value(ctx: &C, value: V) -> Self {
        match ctx.role() {
            Role::H1 => Self::new(value, V::ZERO),
            Role::H2 => Self::new(V::ZERO, V::ZERO),
            Role::H3 => Self::new(V::ZERO, value),
        }
    }
}

#[cfg(feature = "descriptive-gate")]
impl<'a, F: ExtendableField> ShareKnownValue<UpgradedMaliciousContext<'a, F>, F>
    for MaliciousReplicated<F>
{
    fn share_known_value(ctx: &UpgradedMaliciousContext<'a, F>, value: F) -> Self {
        ctx.share_known_value(value)
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use rand::Rng;

    use super::ShareKnownValue;
    use crate::{
        ff::Fp31,
        secret_sharing::replicated::{
            malicious::AdditiveShare as MaliciousReplicated,
            semi_honest::AdditiveShare as Replicated,
        },
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn semi_honest_share_known_values() {
        let world = TestWorld::default();

        let mut rng = rand::thread_rng();
        let a = rng.gen::<Fp31>();

        let result = world
            .semi_honest((), |ctx, ()| async move {
                Replicated::<Fp31>::share_known_value(&ctx, a)
            })
            .await
            .reconstruct();
        assert_eq!(result, a);
    }

    #[tokio::test]
    pub async fn malicious_share_known_values() {
        let world = TestWorld::default();

        let mut rng = rand::thread_rng();
        let a = rng.gen::<Fp31>();

        let result = world
            .upgraded_malicious((), |ctx, ()| async move {
                MaliciousReplicated::<Fp31>::share_known_value(&ctx, a)
            })
            .await
            .reconstruct();
        assert_eq!(result, a);
    }
}
