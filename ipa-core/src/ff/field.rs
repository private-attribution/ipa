use std::{
    fmt::Debug,
    ops::{Mul, MulAssign},
};

use serde::{Deserialize, Serialize};
use typenum::{U1, U4, U8};

use crate::{
    ff::MultiplyAccumulate,
    protocol::prss::FromRandom,
    secret_sharing::{Block, FieldVectorizable, SharedValue, Vectorizable},
};

impl Block for u8 {
    type Size = U1;
}

impl Block for u32 {
    type Size = U4;
}

impl Block for u64 {
    type Size = U8;
}

/// Trait for field elements.
///
/// Basic functionality (Clone, Eq, Debug) and an addition operation are inherited from `SharedValue`.
pub trait Field:
    SharedValue
    + Mul<Self, Output = Self>
    + MulAssign<Self>
    + MultiplyAccumulate
    + FromRandom
    + Into<Self::Storage>
    + Vectorizable<1>
    + FieldVectorizable<1, ArrayAlias = <Self as Vectorizable<1>>::Array>
{
    // Name of the field
    const NAME: &'static str;

    /// Multiplicative identity element
    const ONE: Self;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum FieldType {
    #[cfg(any(test, feature = "weak-field"))]
    Fp31,
    Fp32BitPrime,
}
