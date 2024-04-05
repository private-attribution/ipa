//! Supported vectorizations

use crate::{
    const_assert_eq,
    ff::{
        boolean::Boolean,
        boolean_array::{BA16, BA20, BA256, BA3, BA32, BA5, BA64, BA8},
        ec_prime_field::Fp25519,
        Fp32BitPrime,
    },
    protocol::ipa_prf::{MK_BITS, PRF_CHUNK},
    secret_sharing::{
        replicated::semi_honest::AdditiveShare, BitDecomposed, FieldSimd, FieldVectorizable,
        ReplicatedSecretSharing, SharedValue, Vectorizable,
    },
};

impl FieldSimd<32> for Fp32BitPrime {}

impl FieldSimd<PRF_CHUNK> for Fp25519 {}

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
    ($width:expr, $dim:expr) => {
        <$crate::secret_sharing::BoolVectorLookup as $crate::secret_sharing::BoolVectorTrait<
            $width,
            $dim,
        >>::Share
    };
}

pub trait BoolVectorTrait<const B: usize, const N: usize> {
    type Share;
}

pub struct BoolVectorLookup;

const_assert_eq!(
    MK_BITS,
    64,
    "Appropriate BoolVectorTrait implementation required"
);
impl BoolVectorTrait<64, 1> for BoolVectorLookup {
    type Share = AdditiveShare<BA64>;
}

const_assert_eq!(
    Fp25519::BITS,
    256,
    "Appropriate BoolVectorTrait implementation required"
);
impl BoolVectorTrait<256, 1> for BoolVectorLookup {
    type Share = AdditiveShare<BA256>;
}

impl<const B: usize> BoolVectorTrait<B, PRF_CHUNK> for BoolVectorLookup {
    type Share = BitDecomposed<AdditiveShare<Boolean, PRF_CHUNK>>;
}
