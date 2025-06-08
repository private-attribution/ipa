use crate::{
    helpers::Role,
    protocol::context::Context,
    secret_sharing::{
        SharedValue,
        replicated::{ReplicatedSecretSharing, semi_honest::AdditiveShare as Replicated},
    },
};

/// Produce a share of some pre-determined constant.
///
/// The context is only used to determine the helper role. It is not used for communication or PRSS,
/// and it is not necessary to use a uniquely narrowed context.
///
/// As of Aug 2024, this interface does not work for MAC malicious sharings as they
/// were defined before. Sharing known value requires `r` and it varies from one
/// record id to another. If we need to update this, [`Self::share_known_value`] needs
/// to have record id parameter.
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

#[cfg(all(test, unit_test))]
mod tests {
    use rand::Rng;

    use super::ShareKnownValue;
    use crate::{
        ff::Fp31,
        secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn semi_honest_share_known_values() {
        let world = TestWorld::default();

        let mut rng = rand::thread_rng();
        let a = rng.r#gen::<Fp31>();

        let result = world
            .semi_honest((), |ctx, ()| async move {
                Replicated::<Fp31>::share_known_value(&ctx, a)
            })
            .await
            .reconstruct();
        assert_eq!(result, a);
    }
}
