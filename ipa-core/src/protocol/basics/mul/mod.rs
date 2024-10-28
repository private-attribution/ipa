use std::{
    future::Future,
    ops::{Add, Sub},
};

use async_trait::async_trait;

use crate::{
    error::Error,
    ff::{
        boolean::Boolean,
        boolean_array::{BA16, BA20, BA256, BA3, BA32, BA5, BA64, BA8},
        Expand,
    },
    protocol::{
        basics::PrimeField,
        context::{
            dzkp_semi_honest::DZKPUpgraded as SemiHonestDZKPUpgraded,
            semi_honest::Upgraded as SemiHonestUpgraded, Context, DZKPUpgradedMaliciousContext,
        },
        RecordId,
    },
    secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
    sharding,
};

mod dzkp_malicious;
pub(crate) mod malicious;
mod semi_honest;
pub(crate) mod step;

pub use semi_honest::sh_multiply as semi_honest_multiply;

/// Trait to multiply secret shares. That requires communication and `multiply` function is async.
#[async_trait]
pub trait SecureMul<C: Context>: Send + Sync + Sized {
    /// Multiply and return the result of `a` * `b`.
    async fn multiply<'fut>(&self, rhs: &Self, ctx: C, record_id: RecordId) -> Result<Self, Error>
    where
        C: 'fut;
}

// The BooleanArrayMul trait is implemented for types like `Replicated<BA32>`. It hides the `N`
// const parameter so that implementations parameterized with a Boolean array type parameter (e.g.
// breakdown key type BK is BA8) can invoke vectorized multiply. Without this trait, those
// implementations would need to specify the `N` const parameter, which is tricky, because you
// can't supply an expression involving a type parameter (BK::BITS) as a const parameter.
pub trait BooleanArrayMul<C>: Expand<Input = Replicated<Boolean>> + From<Self::Vectorized>
where
    C: Context,
{
    type Vectorized: From<Self>
        + for<'a> Add<&'a Self::Vectorized, Output = Self::Vectorized>
        + for<'a> Sub<&'a Self::Vectorized, Output = Self::Vectorized>
        + Send
        + Sync
        + 'static;

    fn multiply<'fut>(
        ctx: C,
        record_id: RecordId,
        a: &'fut Self::Vectorized,
        b: &'fut Self::Vectorized,
    ) -> impl Future<Output = Result<Self::Vectorized, Error>> + Send + 'fut
    where
        C: 'fut;
}

// Workaround for https://github.com/rust-lang/rust/issues/100013. Calling this wrapper function
// instead of `<_ as BooleanArrayMul>::multiply` seems to hide the BooleanArrayMul `impl Future`
// GAT.
pub fn boolean_array_multiply<'fut, C, B>(
    ctx: C,
    record_id: RecordId,
    a: &'fut B::Vectorized,
    b: &'fut B::Vectorized,
) -> impl Future<Output = Result<B::Vectorized, Error>> + Send + 'fut
where
    C: Context + 'fut,
    B: BooleanArrayMul<C>,
{
    B::multiply(ctx, record_id, a, b)
}

macro_rules! boolean_array_mul {
    ($dim:expr, $vec:ty) => {
        impl<'a, B, F> BooleanArrayMul<SemiHonestUpgraded<'a, B, F>> for Replicated<$vec>
        where
            B: sharding::ShardBinding,
            F: PrimeField,
        {
            type Vectorized = Replicated<Boolean, $dim>;

            fn multiply<'fut>(
                ctx: SemiHonestUpgraded<'a, B, F>,
                record_id: RecordId,
                a: &'fut Self::Vectorized,
                b: &'fut Self::Vectorized,
            ) -> impl Future<Output = Result<Self::Vectorized, Error>> + Send + 'fut
            where
                SemiHonestUpgraded<'a, B, F>: 'fut,
            {
                semi_honest_multiply(ctx, record_id, a, b)
            }
        }

        impl<'a, B> BooleanArrayMul<SemiHonestDZKPUpgraded<'a, B>> for Replicated<$vec>
        where
            B: sharding::ShardBinding,
        {
            type Vectorized = Replicated<Boolean, $dim>;

            fn multiply<'fut>(
                ctx: SemiHonestDZKPUpgraded<'a, B>,
                record_id: RecordId,
                a: &'fut Self::Vectorized,
                b: &'fut Self::Vectorized,
            ) -> impl Future<Output = Result<Self::Vectorized, Error>> + Send + 'fut
            where
                SemiHonestDZKPUpgraded<'a, B>: 'fut,
            {
                semi_honest_multiply(ctx, record_id, a, b)
            }
        }

        impl<'a, B: sharding::ShardBinding> BooleanArrayMul<DZKPUpgradedMaliciousContext<'a, B>>
            for Replicated<$vec>
        {
            type Vectorized = Replicated<Boolean, $dim>;

            fn multiply<'fut>(
                ctx: DZKPUpgradedMaliciousContext<'a, B>,
                record_id: RecordId,
                a: &'fut Self::Vectorized,
                b: &'fut Self::Vectorized,
            ) -> impl Future<Output = Result<Self::Vectorized, Error>> + Send + 'fut
            where
                DZKPUpgradedMaliciousContext<'a, B>: 'fut,
            {
                use crate::protocol::basics::mul::dzkp_malicious::zkp_multiply;
                zkp_multiply(ctx, record_id, a, b)
            }
        }
    };
}

boolean_array_mul!(3, BA3);
boolean_array_mul!(5, BA5);
boolean_array_mul!(8, BA8);
boolean_array_mul!(16, BA16);
boolean_array_mul!(20, BA20);
boolean_array_mul!(32, BA32);
boolean_array_mul!(64, BA64);
boolean_array_mul!(256, BA256);
