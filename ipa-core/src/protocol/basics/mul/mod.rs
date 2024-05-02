use std::{
    future::Future,
    ops::{Add, Sub},
};

use async_trait::async_trait;

use crate::{
    error::Error,
    ff::{
        boolean::Boolean,
        boolean_array::{BA20, BA3, BA32, BA5, BA64, BA8},
        Expand,
    },
    protocol::{context::Context, RecordId},
    secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
};

#[cfg(feature = "descriptive-gate")]
pub(crate) mod malicious;
mod semi_honest;
pub(in crate::protocol) mod sparse;

#[cfg(feature = "descriptive-gate")]
pub use semi_honest::multiply as semi_honest_multiply;
pub use sparse::{MultiplyZeroPositions, ZeroPositions};

/// Trait to multiply secret shares. That requires communication and `multiply` function is async.
#[async_trait]
pub trait SecureMul<C: Context>: Send + Sync + Sized {
    /// Multiply and return the result of `a` * `b`.
    async fn multiply<'fut>(&self, rhs: &Self, ctx: C, record_id: RecordId) -> Result<Self, Error>
    where
        C: 'fut,
    {
        self.multiply_sparse(rhs, ctx, record_id, ZeroPositions::NONE)
            .await
    }

    /// Multiply and return the result of `a` * `b`.
    /// This takes a profile of which helpers are expected to send
    /// in the form (self, left, right).
    /// This is the implementation you should invoke if you want to
    /// save work when you have sparse values.
    async fn multiply_sparse<'fut>(
        &self,
        rhs: &Self,
        ctx: C,
        record_id: RecordId,
        zeros_at: MultiplyZeroPositions,
    ) -> Result<Self, Error>
    where
        C: 'fut;
}

use semi_honest::multiply as semi_honest_mul;

// The BooleanArrayMul trait is implemented for types like `Replicated<BA32>`. It hides the `N`
// const parameter so that implementations parameterized with a Boolean array type parameter (e.g.
// breakdown key type BK is BA8) can invoke vectorized multiply. Without this trait, those
// implementations would need to specify the `N` const parameter, which is tricky, because you
// can't supply an expression involving a type parameter (BK::BITS) as a const parameter.
pub trait BooleanArrayMul: Expand<Input = Replicated<Boolean>> + From<Self::Vectorized> {
    type Vectorized: From<Self>
        + for<'a> Add<&'a Self::Vectorized, Output = Self::Vectorized>
        + for<'a> Sub<&'a Self::Vectorized, Output = Self::Vectorized>
        + Send
        + Sync
        + 'static;

    fn multiply<'fut, C>(
        ctx: C,
        record_id: RecordId,
        a: &'fut Self::Vectorized,
        b: &'fut Self::Vectorized,
    ) -> impl Future<Output = Result<Self::Vectorized, Error>> + Send + 'fut
    where
        C: Context + 'fut;
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
    B: BooleanArrayMul,
{
    B::multiply(ctx, record_id, a, b)
}

macro_rules! boolean_array_mul {
    ($dim:expr, $vec:ty) => {
        impl BooleanArrayMul for Replicated<$vec> {
            type Vectorized = Replicated<Boolean, $dim>;

            fn multiply<'fut, C>(
                ctx: C,
                record_id: RecordId,
                a: &'fut Self::Vectorized,
                b: &'fut Self::Vectorized,
            ) -> impl Future<Output = Result<Self::Vectorized, Error>> + Send + 'fut
            where
                C: Context + 'fut,
            {
                semi_honest_mul(ctx, record_id, a, b, ZeroPositions::NONE)
            }
        }
    };
}

boolean_array_mul!(3, BA3);
boolean_array_mul!(5, BA5);
boolean_array_mul!(8, BA8);
boolean_array_mul!(20, BA20);
boolean_array_mul!(32, BA32);
boolean_array_mul!(64, BA64);
