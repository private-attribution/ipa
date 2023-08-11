use std::fmt::Debug;

use super::SharedValue;
use crate::ff::{ArithmeticRefOps, GaloisField};

/// Secret sharing scheme i.e. Replicated secret sharing
pub trait SecretSharing<V: SharedValue>: Clone + Debug + Sized + Send + Sync {
    const ZERO: Self;
}

/// Secret share of a secret that has additive and multiplicative properties.
pub trait Linear<V: SharedValue>: SecretSharing<V> + ArithmeticRefOps<V> {}

/// Secret share of a secret in bits. It has additive and multiplicative properties.
pub trait Bitwise<V: GaloisField>: SecretSharing<V> + Linear<V> {}
