pub(crate) mod aggregation;
pub mod boolean_ops;
pub mod oprf_padding;
pub mod prf_eval;
pub mod prf_sharding;

mod malicious_security;
mod quicksort;
pub(crate) mod shuffle;
pub(crate) mod step;
pub mod validation_protocol;

pub use malicious_security::{
    CompressedProofGenerator, FirstProofGenerator, LagrangeTable, ProverTableIndices,
    VerifierTableIndices,
};
pub use shuffle::Shuffle;

use crate::{
    ff::{
        boolean_array::{BooleanArray, BA5, BA64, BA8},
        U128Conversions,
    },
    secret_sharing::SharedValue,
};

/// Match key type
pub type MatchKey = BA64;
/// Match key size
pub const MK_BITS: usize = BA64::BITS as usize;

// In theory, we could support (runtime-configured breakdown count) ≤ (compile-time breakdown count)
// ≤ 2^|bk|, with all three values distinct, but at present, there is no runtime configuration and
// the latter two must be equal. The implementation of `move_single_value_to_bucket` does support a
// runtime-specified count via the `breakdown_count` parameter, and implements a runtime check of
// its value.
//
// It would usually be more appropriate to make `MAX_BREAKDOWNS` an associated constant rather than
// a const parameter. However, we want to use it to enforce a correct pairing of the `BK` type
// parameter and the `B` const parameter, and specifying a constraint like
// `BreakdownKey<MAX_BREAKDOWNS = B>` on an associated constant is not currently supported. (Nor is
// supplying an associated constant `<BK as BreakdownKey>::MAX_BREAKDOWNS` as the value of a const
// parameter.) Structured the way we have it, it probably doesn't make sense to use the
// `BreakdownKey` trait in places where the `B` const parameter is not already available.
pub trait BreakdownKey<const MAX_BREAKDOWNS: usize>: BooleanArray + U128Conversions {}
impl BreakdownKey<32> for BA5 {}
impl BreakdownKey<256> for BA8 {}

/// Vectorization dimension for share conversion
pub const CONV_CHUNK: usize = 256;

/// Vectorization dimension for PRF
pub const PRF_CHUNK: usize = 16;

/// Vectorization dimension for aggregation.
pub const AGG_CHUNK: usize = 256;

/// Vectorization dimension for sort.
pub const SORT_CHUNK: usize = 256;
