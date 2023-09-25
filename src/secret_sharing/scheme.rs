use std::fmt::Debug;
use std::ops::{Mul, Neg};

use super::SharedValue;
use crate::ff::{GaloisField, LocalArithmeticOps, LocalAssignOps};

/// Secret sharing scheme i.e. Replicated secret sharing
pub trait SecretSharing<V: SharedValue>: Clone + Debug + Sized + Send + Sync {
    const ZERO: Self;
}

/// Secret share of a secret that has additive and multiplicative properties.
pub trait Linear<V: SharedValue>: SecretSharing<V>
    + LocalArithmeticOps
    + LocalAssignOps
    + for<'r> LocalArithmeticOps<&'r Self>
    + for<'r> LocalAssignOps<&'r Self>
    // TODO: add reference
    + Mul<V, Output=Self>
    + Neg<Output=Self>
{}

pub trait RefLocalArithmeticOps<'a, Base: 'a>: LocalArithmeticOps<Base, Base> + LocalArithmeticOps<&'a Base, Base> {}
impl<'a, T, Base: 'a> RefLocalArithmeticOps<'a, Base> for T where T: LocalArithmeticOps<Base, Base> + LocalArithmeticOps<&'a Base, Base> + 'a {}

/// Secret share of a secret in bits. It has additive and multiplicative properties.
pub trait Bitwise<V: GaloisField>: SecretSharing<V> + Linear<V> {}
