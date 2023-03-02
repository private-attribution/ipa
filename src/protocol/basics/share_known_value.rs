use crate::{
    bits::Fp2Array,
    ff::Field,
    helpers::Role,
    protocol::context::{Context, MaliciousContext, SemiHonestContext},
    secret_sharing::{
        replicated::{
            malicious::AdditiveShare as MaliciousReplicated,
            semi_honest::{AdditiveShare as Replicated, XorShare},
            ReplicatedSecretSharing,
        },
        SharedValue,
    },
};

pub trait ShareKnownValue<C: Context, V: SharedValue> {
    fn share_known_value(ctx: &C, value: V) -> Self;
}

impl<'a, F: Field> ShareKnownValue<SemiHonestContext<'a>, F> for Replicated<F> {
    fn share_known_value(ctx: &SemiHonestContext<'a>, value: F) -> Self {
        match ctx.role() {
            Role::H1 => Self::new(value, F::ZERO),
            Role::H2 => Self::new(F::ZERO, F::ZERO),
            Role::H3 => Self::new(F::ZERO, value),
        }
    }
}

impl<'a, V: Fp2Array> ShareKnownValue<SemiHonestContext<'a>, V> for XorShare<V> {
    fn share_known_value(ctx: &SemiHonestContext<'a>, value: V) -> Self {
        match ctx.role() {
            Role::H1 => Self::new(value, V::ZERO),
            Role::H2 => Self::new(V::ZERO, V::ZERO),
            Role::H3 => Self::new(V::ZERO, value),
        }
    }
}

impl<'a, F: Field> ShareKnownValue<MaliciousContext<'a, F>, F> for MaliciousReplicated<F> {
    fn share_known_value(ctx: &MaliciousContext<'a, F>, value: F) -> Self {
        ctx.share_known_value(value)
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::ShareKnownValue;
    use crate::{
        ff::Fp31,
        secret_sharing::replicated::{
            malicious::AdditiveShare as MaliciousReplicated,
            semi_honest::AdditiveShare as Replicated,
        },
        test_fixture::{Reconstruct, Runner, TestWorld},
    };
    use rand::Rng;

    #[tokio::test]
    pub async fn semi_honest_share_known_values() {
        let world = TestWorld::new().await;

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
        let world = TestWorld::new().await;

        let mut rng = rand::thread_rng();
        let a = rng.gen::<Fp31>();

        let result = world
            .malicious((), |ctx, ()| async move {
                MaliciousReplicated::<Fp31>::share_known_value(&ctx, a)
            })
            .await
            .reconstruct();
        assert_eq!(result, a);
    }
}
