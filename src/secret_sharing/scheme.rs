use std::{
    fmt::Debug,
    ops::{Mul, Neg},
};

use super::SharedValue;
use crate::ff::{AddSub, AddSubAssign, GaloisField};

/// Secret sharing scheme i.e. Replicated secret sharing
pub trait SecretSharing<V: SharedValue>: Clone + Debug + Sized + Send + Sync {
    const ZERO: Self;
}

/// Secret share of a secret that has additive and multiplicative properties.
pub trait Linear<V: SharedValue>:
    SecretSharing<V>
    + AddSub
    + AddSubAssign
    + for<'r> AddSub<&'r Self>
    + for<'r> AddSubAssign<&'r Self>
    + Mul<V, Output = Self>
    + for<'r> Mul<&'r V, Output = Self>
    + Neg<Output = Self>
{
}

/// The trait for arithmetic operations on references to a secret share, taking the
/// second operand either by value or by reference. Secret sharings can be added/subtracted and
/// multiplied by the shared values locally.
///
/// The need for this trait is dictated by [`rust-issue`] that causes us not being able to constrain
/// references to `Self`. Once this issue is fixed, we can simply get rid of it.
///
/// This is automatically implemented for types which implement the operators. The idea is borrowed
/// from [`RefNum`] trait, but I couldn't really make it work with HRTB and secret shares. Primitive
/// types worked just fine though, so it is possible that it is another compiler issue.
///
/// [`RefNum`]: https://docs.rs/num/0.4.1/num/traits/trait.RefNum.html
/// [`rust-issue`]: https://github.com/rust-lang/rust/issues/20671
pub trait LinearRefOps<'a, Base: 'a, R: 'a>:
    AddSub<Base, Base> + AddSub<&'a Base, Base> + Mul<R, Output = Base> + Mul<&'a R, Output = Base>
{
}
impl<'a, T, Base: 'a, R: 'a> LinearRefOps<'a, Base, R> for T where
    T: AddSub<Base, Base>
        + AddSub<&'a Base, Base>
        + 'a
        + Mul<R, Output = Base>
        + Mul<&'a R, Output = Base>
{
}

/// Secret share of a secret in bits. It has additive and multiplicative properties.
pub trait Bitwise<V: GaloisField>: SecretSharing<V> + Linear<V> {}
