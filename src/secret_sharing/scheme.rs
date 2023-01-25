use super::{ArithmeticShare, BooleanShare, SharedValue};
use crate::bits::BooleanRefOps;
use crate::ff::ArithmeticRefOps;
use std::fmt::Debug;

/// Secret sharing scheme i.e. Replicated secret sharing
pub trait SecretSharing<V: SharedValue>: Clone + Debug + Sized + Send + Sync {
    const ZERO: Self;
}
/// Secret share of a secret that has additive and multiplicative properties.
pub trait Arithmetic<V: ArithmeticShare>: SecretSharing<V> + ArithmeticRefOps<V> {}

/// Secret share of a secret with bit operations
pub trait Boolean<V: BooleanShare>: SecretSharing<V> + BooleanRefOps {}
