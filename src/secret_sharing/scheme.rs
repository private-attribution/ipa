use super::SharedValue;
use crate::bits::{BooleanRefOps, Fp2Array};
use crate::ff::ArithmeticRefOps;
use std::fmt::Debug;

/// Secret sharing scheme i.e. Replicated secret sharing
pub trait SecretSharing<V: SharedValue>:
    Clone + Debug + Sized + Send + Sync + ArithmeticRefOps<V>
{
    const ZERO: Self;
}

/// Secret share of a secret with bit operations
pub trait Boolean<V: Fp2Array>: SecretSharing<V> + BooleanRefOps {}
