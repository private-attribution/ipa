use bitvec::{array::BitArray, order::Lsb0};
use generic_array::GenericArray;
use typenum::U32;

use crate::{
    ff::{Field, Fp61BitPrime, PrimeField},
    protocol::context::dzkp_validator::{BitArray32, SegmentEntry},
};

pub type InitialRecursionFactor = U32;
pub type UVPolynomials<F> = (
    GenericArray<F, InitialRecursionFactor>,
    GenericArray<F, InitialRecursionFactor>,
);
pub type SingleUVPolynomial<F> = GenericArray<F, InitialRecursionFactor>;

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

    /// Convert allows to convert individual bits from multiplication gates into dzkp compatible field elements.
    /// This function is called by the prover.
    fn convert_prover<'a>(
        x_left: &'a BitArray32,
        x_right: &'a BitArray32,
        y_left: &'a BitArray32,
        y_right: &'a BitArray32,
        prss_right: &'a BitArray32,
    ) -> impl Iterator<Item = UVPolynomials<Self>>;

    /// This is similar to `convert_prover` except that it is called by the verifier to the left of the prover.
    /// The verifier on the left uses its right shares, since they are consistent with the prover's left shares.
    fn convert_verifier_left<'a>(
        x_right: &'a BitArray32,
        y_right: &'a BitArray32,
        prss_right: &'a BitArray32,
        z_right: &'a BitArray32,
    ) -> impl Iterator<Item = SingleUVPolynomial<Self>>;

    /// This is similar to `convert_prover` except that it is called by the verifier to the right of the prover.
    /// The verifier on the right uses its left shares, since they are consistent with the prover's right shares.
    fn convert_verifier_right<'a>(
        x_left: &'a BitArray32,
        y_left: &'a BitArray32,
        prss_left: &'a BitArray32,
    ) -> impl Iterator<Item = SingleUVPolynomial<Self>>;
}

impl DZKPBaseField for Fp61BitPrime {
    const INVERSE_OF_TWO: Self = Fp61BitPrime::const_truncate(1_152_921_504_606_846_976u64);
    const MINUS_ONE_HALF: Self = Fp61BitPrime::const_neg(Self::INVERSE_OF_TWO);
    const MINUS_TWO: Self = Fp61BitPrime::const_neg(Fp61BitPrime::const_truncate(2));

    // Convert allows to convert individual bits from multiplication gates into dzkp compatible field elements
    // We use the conversion logic from https://eprint.iacr.org/2023/909.pdf
    //
    // This function does not use any optimization.
    //
    // Prover and left can compute:
    // g1=-2ac(1-2e),
    // g2=c(1-2e),
    // g3=a(1-2e),
    // g4=-1/2(1-2e),
    //
    // Prover and right can compute:
    // h1=bd(1-2f),
    // h2=d(1-2f),
    // h3=b(1-2f),
    // h4=1-2f,
    //
    // where
    // (a,b,c,d,f) = (x_left, y_right, y_left, x_right, prss_right)
    // and
    // e = ab⊕cd⊕ f
    // e is defined different from the paper here,
    // in the paper e is defined as e = x_left · y_left ⊕ z_left ⊕ prss_left
    // notice that the prover is supposed to show that ab⊕cd⊕ f⊕ e =0
    // therefore e = ab⊕cd⊕ f must hold. (alternatively, you can also see this by substituting z_left,
    // i.e. z_left = x_left · y_left ⊕ x_left · y_right ⊕ x_right · y_left ⊕ prss_left ⊕ prss_right
    fn convert_prover<'a>(
        x_left: &'a BitArray32,
        x_right: &'a BitArray32,
        y_left: &'a BitArray32,
        y_right: &'a BitArray32,
        prss_right: &'a BitArray32,
    ) -> impl Iterator<Item = UVPolynomials<Fp61BitPrime>> {
        x_left
            .chunks(RECURSION_CHUNK_SIZE)
            .zip(y_right.chunks(RECURSION_CHUNK_SIZE))
            .zip(y_left.chunks(RECURSION_CHUNK_SIZE))
            .zip(x_right.chunks(RECURSION_CHUNK_SIZE))
            .zip(prss_right.chunks(RECURSION_CHUNK_SIZE))
            .map(|((((a, b), c), d), f)| {
                // e = ab⊕cd⊕ f = x_left * y_right ⊕ y_left * x_right ⊕ prss_right
                let e: BitArray<[u8; RECURSION_CHUNK_SIZE >> 3], Lsb0> = (BitArray::try_from(a)
                    .unwrap()
                    & BitArray::<[u8; RECURSION_CHUNK_SIZE >> 3], Lsb0>::try_from(b).unwrap())
                    ^ (BitArray::<[u8; RECURSION_CHUNK_SIZE >> 3], Lsb0>::try_from(c).unwrap()
                        & BitArray::<[u8; RECURSION_CHUNK_SIZE >> 3], Lsb0>::try_from(d).unwrap())
                    ^ BitArray::<[u8; RECURSION_CHUNK_SIZE >> 3], Lsb0>::try_from(f).unwrap();
                // precompute ac = a & c
                let ac: BitArray<[u8; RECURSION_CHUNK_SIZE >> 3], Lsb0> = BitArray::try_from(a)
                    .unwrap()
                    & BitArray::<[u8; RECURSION_CHUNK_SIZE >> 3], Lsb0>::try_from(c).unwrap();
                // precompute bd = b & d
                let bd: BitArray<[u8; RECURSION_CHUNK_SIZE >> 3], Lsb0> = BitArray::try_from(b)
                    .unwrap()
                    & BitArray::<[u8; RECURSION_CHUNK_SIZE >> 3], Lsb0>::try_from(d).unwrap();
                (
                    // g polynomial
                    a.iter()
                        .zip(c.iter())
                        .zip(e.iter())
                        .zip(ac.iter())
                        .flat_map(|(((a, c), e), ac)| {
                            let one_minus_two_e = Fp61BitPrime::ONE
                                + Fp61BitPrime::MINUS_TWO * Fp61BitPrime::from_bit(*e);
                            [
                                // g1=-2ac(1-2e),
                                Fp61BitPrime::MINUS_TWO
                                    * Fp61BitPrime::from_bit(*ac)
                                    * one_minus_two_e,
                                // g2=c(1-2e),
                                Fp61BitPrime::from_bit(*c) * one_minus_two_e,
                                // g3=a(1-2e),
                                Fp61BitPrime::from_bit(*a) * one_minus_two_e,
                                // g4=-1/2(1-2e),
                                Fp61BitPrime::MINUS_ONE_HALF * one_minus_two_e,
                            ]
                        })
                        .collect::<GenericArray<Fp61BitPrime, InitialRecursionFactor>>(),
                    // h polynomial
                    b.iter()
                        .zip(d.iter())
                        .zip(f.iter())
                        .zip(bd.iter())
                        .flat_map(|(((b, d), f), bd)| {
                            let one_minus_two_f = Fp61BitPrime::ONE
                                + Fp61BitPrime::MINUS_TWO * Fp61BitPrime::from_bit(*f);
                            [
                                // h1=bd(1-2f),
                                Fp61BitPrime::from_bit(*bd) * one_minus_two_f,
                                // h2=d(1-2f),
                                Fp61BitPrime::from_bit(*d) * one_minus_two_f,
                                // h3=b(1-2f),
                                Fp61BitPrime::from_bit(*b) * one_minus_two_f,
                                // h4=1-2f,
                                one_minus_two_f,
                            ]
                        })
                        .collect::<GenericArray<Fp61BitPrime, InitialRecursionFactor>>(),
                )
            })
    }

    // Convert allows to convert individual bits from multiplication gates into dzkp compatible field elements
    // We use the conversion logic from https://eprint.iacr.org/2023/909.pdf
    //
    // This function does not use any optimization.
    //
    //
    // Prover and left can compute:
    // g1=-2ac(1-2e),
    // g2=c(1-2e),
    // g3=a(1-2e),
    // g4=-1/2(1-2e),
    //
    // where
    // (a,c,e) = (xright, yright, xright * yright ⊕ zright ⊕ prssright)
    // here e is defined as in the paper (since the the verifier does not have access to b,d,f,
    // he cannot use the simplified formula for e)
    fn convert_verifier_left<'a>(
        x_right: &'a BitArray32,
        y_right: &'a BitArray32,
        prss_right: &'a BitArray32,
        z_right: &'a BitArray32,
    ) -> impl Iterator<Item = SingleUVPolynomial<Self>> {
        x_right
            .chunks(RECURSION_CHUNK_SIZE)
            .zip(y_right.chunks(RECURSION_CHUNK_SIZE))
            .zip(prss_right.chunks(RECURSION_CHUNK_SIZE))
            .zip(z_right.chunks(RECURSION_CHUNK_SIZE))
            .map(|(((a, c), prss), z)| {
                // precompute ac = a & c
                let ac: BitArray<[u8; RECURSION_CHUNK_SIZE >> 3], Lsb0> = BitArray::try_from(a)
                    .unwrap()
                    & BitArray::<[u8; RECURSION_CHUNK_SIZE >> 3], Lsb0>::try_from(c).unwrap();
                // e = ac ⊕ zright ⊕ prssright
                // as defined in the paper
                let e: BitArray<[u8; RECURSION_CHUNK_SIZE >> 3], Lsb0> = ac
                    ^ BitArray::<[u8; RECURSION_CHUNK_SIZE >> 3], Lsb0>::try_from(prss).unwrap()
                    ^ BitArray::<[u8; RECURSION_CHUNK_SIZE >> 3], Lsb0>::try_from(z).unwrap();
                // g polynomial
                a.iter()
                    .zip(c.iter())
                    .zip(e.iter())
                    .zip(ac.iter())
                    .flat_map(|(((a, c), e), ac)| {
                        let one_minus_two_e = Fp61BitPrime::ONE
                            + Fp61BitPrime::MINUS_TWO * Fp61BitPrime::from_bit(*e);
                        [
                            // g1=-2ac(1-2e),
                            Fp61BitPrime::MINUS_TWO * Fp61BitPrime::from_bit(*ac) * one_minus_two_e,
                            // g2=c(1-2e),
                            Fp61BitPrime::from_bit(*c) * one_minus_two_e,
                            // g3=a(1-2e),
                            Fp61BitPrime::from_bit(*a) * one_minus_two_e,
                            // g4=-1/2(1-2e),
                            Fp61BitPrime::MINUS_ONE_HALF * one_minus_two_e,
                        ]
                    })
                    .collect::<GenericArray<Fp61BitPrime, InitialRecursionFactor>>()
            })
    }

    // Convert allows to convert individual bits from multiplication gates into dzkp compatible field elements
    // We use the conversion logic from https://eprint.iacr.org/2023/909.pdf
    //
    // This function does not use any optimization.
    //
    //
    // Prover and right can compute:
    // h1=bd(1-2f),
    // h2=d(1-2f),
    // h3=b(1-2f),
    // h4=1-2f,
    //
    // where
    // (b,d,f) = (yleft, xleft, prssleft)
    fn convert_verifier_right<'a>(
        x_left: &'a BitArray32,
        y_left: &'a BitArray32,
        prss_left: &'a BitArray32,
    ) -> impl Iterator<Item = SingleUVPolynomial<Self>> {
        y_left
            .chunks(RECURSION_CHUNK_SIZE)
            .zip(x_left.chunks(RECURSION_CHUNK_SIZE))
            .zip(prss_left.chunks(RECURSION_CHUNK_SIZE))
            .map(|((b, d), f)| {
                // precompute bd = b & d
                let bd: BitArray<[u8; RECURSION_CHUNK_SIZE >> 3], Lsb0> = BitArray::try_from(b)
                    .unwrap()
                    & BitArray::<[u8; RECURSION_CHUNK_SIZE >> 3], Lsb0>::try_from(d).unwrap();
                // h polynomial
                b.iter()
                    .zip(d.iter())
                    .zip(f.iter())
                    .zip(bd.iter())
                    .flat_map(|(((b, d), f), bd)| {
                        let one_minus_two_f = Fp61BitPrime::ONE
                            + Fp61BitPrime::MINUS_TWO * Fp61BitPrime::from_bit(*f);
                        [
                            // h1=bd(1-2f),
                            Fp61BitPrime::from_bit(*bd) * one_minus_two_f,
                            // h2=d(1-2f),
                            Fp61BitPrime::from_bit(*d) * one_minus_two_f,
                            // h3=b(1-2f),
                            Fp61BitPrime::from_bit(*b) * one_minus_two_f,
                            // h4=1-2f,
                            one_minus_two_f,
                        ]
                    })
                    .collect::<GenericArray<Fp61BitPrime, InitialRecursionFactor>>()
            })
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use bitvec::{array::BitArray, slice::BitSlice};
    use rand::{thread_rng, Rng};

    use crate::{
        ff::Fp61BitPrime,
        protocol::context::dzkp_field::{DZKPBaseField, SingleUVPolynomial, UVPolynomials},
    };

    #[test]
    fn batch_convert() {
        let mut rng = thread_rng();

        // bitvecs
        let mut vec_x_left = Vec::<u8>::new();
        let mut vec_x_right = Vec::<u8>::new();
        let mut vec_y_left = Vec::<u8>::new();
        let mut vec_y_right = Vec::<u8>::new();
        let mut vec_prss_left = Vec::<u8>::new();
        let mut vec_prss_right = Vec::<u8>::new();
        let mut vec_z_right = Vec::<u8>::new();

        // gen 32 random values
        for _i in 0..32 {
            let x_left: u8 = rng.gen();
            let x_right: u8 = rng.gen();
            let y_left: u8 = rng.gen();
            let y_right: u8 = rng.gen();
            let prss_left: u8 = rng.gen();
            let prss_right: u8 = rng.gen();
            // we set this up to be equal to z_right for this local test
            // local here means that only a single party is involved
            // and we just test this against this single party
            let z_right: u8 = (x_left & y_left)
                ^ (x_left & y_right)
                ^ (x_right & y_left)
                ^ prss_left
                ^ prss_right;

            // fill vec
            vec_x_left.push(x_left);
            vec_x_right.push(x_right);
            vec_y_left.push(y_left);
            vec_y_right.push(y_right);
            vec_prss_left.push(prss_left);
            vec_prss_right.push(prss_right);
            vec_z_right.push(z_right);
        }

        // conv to BitVec
        let x_left = BitArray::<[u8; 32]>::try_from(BitSlice::from_slice(&vec_x_left)).unwrap();
        let x_right = BitArray::<[u8; 32]>::try_from(BitSlice::from_slice(&vec_x_right)).unwrap();
        let y_left = BitArray::<[u8; 32]>::try_from(BitSlice::from_slice(&vec_y_left)).unwrap();
        let y_right = BitArray::<[u8; 32]>::try_from(BitSlice::from_slice(&vec_y_right)).unwrap();
        let prss_left =
            BitArray::<[u8; 32]>::try_from(BitSlice::from_slice(&vec_prss_left)).unwrap();
        let prss_right =
            BitArray::<[u8; 32]>::try_from(BitSlice::from_slice(&vec_prss_right)).unwrap();
        let z_right = BitArray::<[u8; 32]>::try_from(BitSlice::from_slice(&vec_z_right)).unwrap();

        // check consistency of the polynomials
        assert_convert(
            Fp61BitPrime::convert_prover(&x_left, &x_right, &y_left, &y_right, &prss_right),
            // flip intputs right to left since it is checked against itself and not party on the left
            // z_right is set to match z_left
            Fp61BitPrime::convert_verifier_left(&x_left, &y_left, &prss_left, &z_right),
            // flip intputs right to left since it is checked against itself and not party on the left
            Fp61BitPrime::convert_verifier_right(&x_right, &y_right, &prss_right),
        );
    }
    fn assert_convert<P, L, R>(prover: P, verifier_left: L, verifier_right: R)
    where
        P: Iterator<Item = UVPolynomials<Fp61BitPrime>>,
        L: Iterator<Item = SingleUVPolynomial<Fp61BitPrime>>,
        R: Iterator<Item = SingleUVPolynomial<Fp61BitPrime>>,
    {
        prover.zip(verifier_left).zip(verifier_right).for_each(
            |((prover, verifier_left), verifier_right)| {
                assert_eq!(prover.0, verifier_left);
                assert_eq!(prover.1, verifier_right);
            },
        );
    }
}
