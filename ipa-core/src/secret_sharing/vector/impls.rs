//! Supported vectorizations

use crate::{
    ff::{
        boolean::Boolean,
        boolean_array::{BA16, BA20, BA256, BA3, BA32, BA5, BA64, BA8},
        ec_prime_field::Fp25519,
        Fp32BitPrime, Gf32Bit,
    },
    protocol::{
        context::{dzkp_field::DZKPCompatibleField, dzkp_validator::SegmentEntry},
        ipa_prf::PRF_CHUNK,
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare, FieldSimd, FieldVectorizable,
        ReplicatedSecretSharing, Vectorizable,
    },
};

impl FieldSimd<32> for Fp32BitPrime {}
impl FieldSimd<32> for Gf32Bit {}

impl FieldSimd<PRF_CHUNK> for Fp25519 {}

macro_rules! boolean_vector {
    ($modname:ident, $dim:expr, $vec:ty) => {
        mod $modname {
            use super::*;

            impl Vectorizable<$dim> for Boolean {
                type Array = $vec;
            }

            impl FieldVectorizable<$dim> for Boolean {
                type ArrayAlias = $vec;
            }

            impl FieldSimd<$dim> for Boolean {}

            impl DZKPCompatibleField<$dim> for Boolean {
                fn as_segment_entry(
                    array: &<Self as Vectorizable<$dim>>::Array,
                ) -> SegmentEntry<'_> {
                    SegmentEntry::from_bitslice(array.as_bitslice())
                }
            }

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
        }
    };
}

// These macro invocations define the supported vectorization dimensions for `Boolean`.
// The associated BA type must be defined in `ff::boolean_array`.

boolean_vector!(bav_3, 3, BA3);
boolean_vector!(bav_5, 5, BA5);
boolean_vector!(bav_8, 8, BA8);
boolean_vector!(bav_16, 16, BA16);
boolean_vector!(bav_20, 20, BA20);
boolean_vector!(bav_32, 32, BA32);
boolean_vector!(bav_64, 64, BA64);
boolean_vector!(bav_256, 256, BA256);
