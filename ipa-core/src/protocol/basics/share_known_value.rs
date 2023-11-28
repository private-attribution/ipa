use crate::{
    ff::Field,
    helpers::Role,
    protocol::context::{Context, UpgradedContext, UpgradedMaliciousContext},
    secret_sharing::{
        replicated::{
            malicious::{AdditiveShare as MaliciousReplicated, ExtendableField},
            semi_honest::AdditiveShare as Replicated,
            ReplicatedSecretSharing,
        },
        SharedValue,
    },
};

pub trait ShareKnownValue<C: Context, V: SharedValue> {
    fn share_known_value(ctx: &C, value: V) -> Self;
}

impl<C: Context, F: Field> ShareKnownValue<C, F> for Replicated<F> {
    fn share_known_value(ctx: &C, value: F) -> Self {
        match ctx.role() {
            Role::H1 => Self::new(value, F::ZERO),
            Role::H2 => Self::new(F::ZERO, F::ZERO),
            Role::H3 => Self::new(F::ZERO, value),
        }
    }
}

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
