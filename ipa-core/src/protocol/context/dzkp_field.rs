use std::ops::Neg;

use generic_array::GenericArray;
use typenum::U32;

use crate::{
    ff::{Field, Fp61BitPrime, PrimeField, U128Conversions},
    protocol::context::dzkp_validator::{BitArray32, SegmentEntry},
};

pub type InitialRecursionFactor = U32;
pub type UVPolynomials<F> = (
    GenericArray<F, InitialRecursionFactor>,
    GenericArray<F, InitialRecursionFactor>,
);

const RECURSION_CHUNK_SIZE: usize = 8;

/// Trait for fields compatible with DZKPs
/// Field needs to support conversion to `SegmentEntry`, i.e. `to_segment_entry` which is required by DZKPs
#[allow(dead_code)]
pub trait DZKPCompatibleField: Field {
    fn as_segment_entry(&self) -> SegmentEntry<'_>;
}

/// Marker Trait `DZKPBaseField` for fields that can be used as base for DZKP proofs and their verification
/// This is different from trait `DZKPCompatibleField` which is the base for the MPC protocol
pub trait DZKPBaseField: PrimeField {
    const INVERSE_OF_TWO: Self;
    const MINUS_ONE_HALF: Self;
    const MINUS_TWO: Self;

    /// Convert allows to convert individual bits from multiplication gates into dzkp compatible field elements
    /// We use the conversion logic from https://eprint.iacr.org/2023/909.pdf
    ///
    /// This function does not use any optimization.
    ///
    /// Prover and left can compute:
    /// g1=-2ac(1-2e),
    /// g2=c(1-2e),
    /// g3=a(1-2e),
    /// g4=-1/2(1-2e),
    ///
    /// Prover and right can compute:
    /// h1=bd(1-2f),
    /// h2=d(1-2f),
    /// h3=b(1-2f),
    /// h4=1-2f,
    ///
    /// where
    /// (a,b,c,d,f) = (xleft, yright, yleft, xright, prssright)
    /// and
    /// e = e=ab⊕dc⊕ f
    fn convert_prover<'a>(
        x_left: &'a BitArray32,
        x_right: &'a BitArray32,
        y_left: &'a BitArray32,
        y_right: &'a BitArray32,
        prss_right: &'a BitArray32,
    ) -> impl Iterator<Item = UVPolynomials<Self>>;
}

impl DZKPBaseField for Fp61BitPrime {
    const INVERSE_OF_TWO: Self = Fp61BitPrime::const_truncate(1_152_921_504_606_846_976u64);
    const MINUS_ONE_HALF: Self = Self::INVERSE_OF_TWO.neg();
    const MINUS_TWO: Self = (Self::ONE + Self::ONE).neg();

    /// Convert allows to convert individual bits from multiplication gates into dzkp compatible field elements
    /// We use the conversion logic from https://eprint.iacr.org/2023/909.pdf
    ///
    /// This function does not use any optimization.
    ///
    /// Prover and left can compute:
    /// g1=-2ac(1-2e),
    /// g2=c(1-2e),
    /// g3=a(1-2e),
    /// g4=-1/2(1-2e),
    ///
    /// Prover and right can compute:
    /// h1=bd(1-2f),
    /// h2=d(1-2f),
    /// h3=b(1-2f),
    /// h4=1-2f,
    ///
    /// where
    /// (a,b,c,d,f) = (xleft, yright, yleft, xright, prssright)
    /// and
    /// e = ab⊕cd⊕ f
    fn convert_prover<'a>(
        x_left: &'a BitArray32,
        x_right: &'a BitArray32,
        y_left: &'a BitArray32,
        y_right: &'a BitArray32,
        prss_right: &'a BitArray32,
    ) -> impl Iterator<Item = UVPolynomials<Fp61BitPrime>> {
        // e = ab⊕cd⊕ f = x_left * y_right ⊕ y_left * x_right ⊕ prss_right
        let e = (*x_left & *y_right) ^ (*y_left & *x_right) ^ *prss_right;
        // precompute ab
        let a_times_c = *x_left & *y_left;
        // precompute bd
        let b_times_d = *x_right & *y_right;

        x_left
            .chunks(RECURSION_CHUNK_SIZE)
            .zip(y_right.chunks(RECURSION_CHUNK_SIZE))
            .zip(y_left.chunks(RECURSION_CHUNK_SIZE))
            .zip(x_right.chunks(RECURSION_CHUNK_SIZE))
            .zip(prss_right.chunks(RECURSION_CHUNK_SIZE))
            .zip(e.chunks(RECURSION_CHUNK_SIZE))
            .zip(a_times_c.chunks(RECURSION_CHUNK_SIZE))
            .zip(b_times_d.chunks(RECURSION_CHUNK_SIZE))
            .map(|(((((((a, b), c), d), f), e), ac), bd)| {
                (
                    // g polynomial
                    a.iter()
                        .zip(c.iter())
                        .zip(e.iter())
                        .zip(ac.iter())
                        .map(|(((a, c), e), ac)| {
                            let one_minus_two_e = Fp61BitPrime::ONE
                                + Fp61BitPrime::MINUS_TWO * Fp61BitPrime::truncate_from(*e);
                            [
                                // g1=-2ac(1-2e),
                                Fp61BitPrime::MINUS_TWO
                                    * Fp61BitPrime::truncate_from(*ac)
                                    * one_minus_two_e,
                                // g2=c(1-2e),
                                Fp61BitPrime::truncate_from(*c) * one_minus_two_e,
                                // g3=a(1-2e),
                                Fp61BitPrime::truncate_from(*a) * one_minus_two_e,
                                // g4=-1/2(1-2e),
                                Fp61BitPrime::MINUS_ONE_HALF * one_minus_two_e,
                            ]
                        })
                        .flatten()
                        .collect::<GenericArray<Fp61BitPrime, InitialRecursionFactor>>(),
                    // h polynomial
                    b.iter()
                        .zip(d.iter())
                        .zip(f.iter())
                        .zip(bd.iter())
                        .map(|(((b, d), f), bd)| {
                            let one_minus_two_f = Fp61BitPrime::ONE
                                + Fp61BitPrime::MINUS_TWO * Fp61BitPrime::truncate_from(*f);
                            [
                                // h1=bd(1-2f),
                                Fp61BitPrime::truncate_from(*bd) * one_minus_two_f,
                                // h2=d(1-2f),
                                Fp61BitPrime::truncate_from(*d) * one_minus_two_f,
                                // h3=b(1-2f),
                                Fp61BitPrime::truncate_from(*b) * one_minus_two_f,
                                // h4=1-2f,
                                one_minus_two_f,
                            ]
                        })
                        .flatten()
                        .collect::<GenericArray<Fp61BitPrime, InitialRecursionFactor>>(),
                )
            })
    }
}
