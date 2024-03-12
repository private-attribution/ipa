//! Supported vectorizations

use crate::{
    ff::{
        boolean::Boolean,
        boolean_array::{BA16, BA20, BA256, BA3, BA32, BA5, BA64, BA8},
        Fp32BitPrime,
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare, FieldSimd, FieldVectorizable,
        ReplicatedSecretSharing, Vectorizable,
    },
};

impl FieldSimd<32> for Fp32BitPrime {}

macro_rules! boolean_vector {
    ($dim:expr, $vec:ty) => {
        impl Vectorizable<$dim> for Boolean {
            type Array = $vec;
        }

        impl FieldVectorizable<$dim> for Boolean {
            type ArrayAlias = $vec;
        }

        impl FieldSimd<$dim> for Boolean {}

        impl From<AdditiveShare<$vec>> for AdditiveShare<Boolean, $dim> {
            fn from(value: AdditiveShare<$vec>) -> Self {
                AdditiveShare::new_arr(value.left(), value.right())
            }
        }

        impl From<AdditiveShare<Boolean, $dim>> for AdditiveShare<$vec> {
            fn from(value: AdditiveShare<Boolean, $dim>) -> Self {
                AdditiveShare::new(*value.left_arr(), *value.right_arr())
            }
        }
    };
}

boolean_vector!(3, BA3);
boolean_vector!(5, BA5);
boolean_vector!(8, BA8);
boolean_vector!(16, BA16);
boolean_vector!(20, BA20);
boolean_vector!(32, BA32);
boolean_vector!(64, BA64);
boolean_vector!(256, BA256);

/// Expands to the type for storing vectorized shares of a multi-bit boolean value.
///
/// The "width" is the bit width of the value for each record. For example, a breakdown key might
/// have an 8-bit width.
///
/// The "dimension" is the vectorization dimension, which is a number of records. For example,
/// there might be no vectorization (dimension = 1), or computation might be vectorized over
/// 256 records (dimension = 256).
///
/// When the dimension is one, `BoolVector!(width, 1)` expands to an `AdditiveShare` of the Boolean
/// array type with the requested width.
///
/// When the dimension is greater than one, `BoolVector!(width, dim)` expands to
/// `BitDecomposed<AdditiveShare<Boolean, dim>>`.
#[macro_export]
macro_rules! BoolVector {
    (16, 1) => { $crate::secret_sharing::replicated::semi_honest::AdditiveShare<$crate::ff::BA16> };
    ($width:expr, $dim:expr) => { BitDecomposed<$crate::secret_sharing::replicated::semi_honest::AdditiveShare<$crate::ff::boolean::Boolean, $dim>> };
}
