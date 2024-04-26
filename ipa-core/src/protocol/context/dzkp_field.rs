use crate::{
    ff::Field,
    protocol::context::dzkp_validator::{BitArray32, SegmentEntry},
};

/// Trait for fields compatible with DZKPs
/// Field needs to support conversion to `SegmentEntry`, i.e. `to_segment_entry` which is required by DZKPs
#[allow(dead_code)]
pub trait DZKPCompatibleField: Field {
    fn as_segment_entry(&self) -> SegmentEntry<'_>;
}

/// Marker Trait `DZKPBaseField` for fields that can be used as base for DZKP proofs and their verification
/// This is different from trait `DZKPCompatibleField` which is the base for the MPC protocol
pub trait DZKPBaseField: Field {
    type UnverifiedFieldValues;
    fn convert(
        x_left: &BitArray32,
        x_right: &BitArray32,
        y_left: &BitArray32,
        y_right: &BitArray32,
        prss_left: &BitArray32,
        prss_right: &BitArray32,
        z_right: &BitArray32,
    ) -> Self::UnverifiedFieldValues;
}

// TODO(dm) - implement Basefield for Fp61BitPrime in follow up PR

/*
we need to prove that z_left = x_left · y_left ⊕ x_left · y_right ⊕ x_right · y_left ⊕ prss_left ⊕ ρrss_right.
The paper defines:

a := x_left
b := y_right
c := y_left
d := x_right
e := x_left · y_left ⊕ z_left ⊕ prss_left
f := prss_right

We now need to prove:

a · b ⊕ c · d ⊕ e ⊕ f = 0.

xor can be computed via
a ⊕ b = a + b − 2ab mod p = a(1 − 2b) + b mod p
*/
