use generic_array::GenericArray;
use typenum::{Unsigned, U32};

use crate::{
    const_assert, const_assert_eq,
    ff::{Field, Fp61BitPrime, PrimeField},
    protocol::context::dzkp_validator::{Array256Bit, SegmentEntry},
    secret_sharing::{FieldSimd, Vectorizable},
};

pub type InitialRecursionFactor = U32;
pub type UVPolynomials<F> = (
    GenericArray<F, InitialRecursionFactor>,
    GenericArray<F, InitialRecursionFactor>,
);
pub type SingleUVPolynomial<F> = GenericArray<F, InitialRecursionFactor>;
// we only support InitialRecursionFactors of non-zero multiples of 4
const_assert_eq!(InitialRecursionFactor::USIZE % 4, 0usize);
const_assert!(InitialRecursionFactor::USIZE != 0usize);

const RECURSION_CHUNK_SIZE_BITS: usize = InitialRecursionFactor::USIZE / 4;

/// Trait for fields compatible with DZKPs
/// Field needs to support conversion to `SegmentEntry`, i.e. `to_segment_entry` which is required by DZKPs
#[allow(dead_code)]
pub trait DZKPCompatibleField<const N: usize = 1>: FieldSimd<N> {
    fn as_segment_entry(array: &<Self as Vectorizable<N>>::Array) -> SegmentEntry<'_>;
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
        x_left: &'a Array256Bit,
        x_right: &'a Array256Bit,
        y_left: &'a Array256Bit,
        y_right: &'a Array256Bit,
        prss_right: &'a Array256Bit,
    ) -> impl Iterator<Item = UVPolynomials<Self>>;

    /// This is similar to `convert_prover` except that it is called by the verifier to the left of the prover.
    /// The verifier on the left uses its right shares, since they are consistent with the prover's left shares.
    fn convert_verifier_left<'a>(
        x_right: &'a Array256Bit,
        y_right: &'a Array256Bit,
        prss_right: &'a Array256Bit,
        z_right: &'a Array256Bit,
    ) -> impl Iterator<Item = SingleUVPolynomial<Self>>;

    /// This is similar to `convert_prover` except that it is called by the verifier to the right of the prover.
    /// The verifier on the right uses its left shares, since they are consistent with the prover's right shares.
    fn convert_verifier_right<'a>(
        x_left: &'a Array256Bit,
        y_left: &'a Array256Bit,
        prss_left: &'a Array256Bit,
    ) -> impl Iterator<Item = SingleUVPolynomial<Self>>;
}

impl DZKPBaseField for Fp61BitPrime {
    const INVERSE_OF_TWO: Self = Fp61BitPrime::const_truncate(1_152_921_504_606_846_976u64);
    const MINUS_ONE_HALF: Self = Fp61BitPrime::const_truncate(1_152_921_504_606_846_975u64);
    const MINUS_TWO: Self = Fp61BitPrime::const_truncate(2_305_843_009_213_693_949u64);

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
        x_left: &'a Array256Bit,
        x_right: &'a Array256Bit,
        y_left: &'a Array256Bit,
        y_right: &'a Array256Bit,
        prss_right: &'a Array256Bit,
    ) -> impl Iterator<Item = UVPolynomials<Fp61BitPrime>> {
        x_left
            .chunks(RECURSION_CHUNK_SIZE_BITS)
            .map(ToOwned::to_owned)
            .zip(
                y_right
                    .chunks(RECURSION_CHUNK_SIZE_BITS)
                    .map(ToOwned::to_owned),
            )
            .zip(
                y_left
                    .chunks(RECURSION_CHUNK_SIZE_BITS)
                    .map(ToOwned::to_owned),
            )
            .zip(
                x_right
                    .chunks(RECURSION_CHUNK_SIZE_BITS)
                    .map(ToOwned::to_owned),
            )
            .zip(
                prss_right
                    .chunks(RECURSION_CHUNK_SIZE_BITS)
                    .map(ToOwned::to_owned),
            )
            .map(|((((a, b), c), d), f)| {
                // precompute ac = a & c
                let ac = a.clone() & &c;
                // e = ab⊕cd⊕ f = x_left * y_right ⊕ y_left * x_right ⊕ prss_right
                let e = (a.clone() & &b) ^ (c.clone() & &d) ^ &f;
                // precompute bd = b & d
                let bd = b.clone() & &d;
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
    // (a,c,e) = (x_right, y_right, x_right * y_right ⊕ z_right ⊕ prss_right)
    // here e is defined as in the paper (since the the verifier does not have access to b,d,f,
    // he cannot use the simplified formula for e)
    fn convert_verifier_left<'a>(
        x_right: &'a Array256Bit,
        y_right: &'a Array256Bit,
        prss_right: &'a Array256Bit,
        z_right: &'a Array256Bit,
    ) -> impl Iterator<Item = SingleUVPolynomial<Self>> {
        x_right
            .chunks(RECURSION_CHUNK_SIZE_BITS)
            .map(ToOwned::to_owned)
            .zip(
                y_right
                    .chunks(RECURSION_CHUNK_SIZE_BITS)
                    .map(ToOwned::to_owned),
            )
            .zip(
                prss_right
                    .chunks(RECURSION_CHUNK_SIZE_BITS)
                    .map(ToOwned::to_owned),
            )
            .zip(
                z_right
                    .chunks(RECURSION_CHUNK_SIZE_BITS)
                    .map(ToOwned::to_owned),
            )
            .map(|(((a, c), prss), z)| {
                // precompute ac = a & c
                let ac = a.clone() & &c;
                // e = ac ⊕ zright ⊕ prssright
                // as defined in the paper
                let e = ac.clone() ^ &prss ^ &z;
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
    // (b,d,f) = (y_left, x_left, prss_left)
    fn convert_verifier_right<'a>(
        x_left: &'a Array256Bit,
        y_left: &'a Array256Bit,
        prss_left: &'a Array256Bit,
    ) -> impl Iterator<Item = SingleUVPolynomial<Self>> {
        y_left
            .chunks(RECURSION_CHUNK_SIZE_BITS)
            .map(ToOwned::to_owned)
            .zip(
                x_left
                    .chunks(RECURSION_CHUNK_SIZE_BITS)
                    .map(ToOwned::to_owned),
            )
            .zip(
                prss_left
                    .chunks(RECURSION_CHUNK_SIZE_BITS)
                    .map(ToOwned::to_owned),
            )
            .map(|((b, d), f)| {
                // precompute bd = b & d
                let bd = b.clone() & &d;
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
    use bitvec::{array::BitArray, macros::internal::funty::Fundamental, slice::BitSlice};
    use proptest::proptest;
    use rand::{thread_rng, Rng};

    use crate::{
        ff::{Field, Fp61BitPrime, U128Conversions},
        protocol::context::dzkp_field::{DZKPBaseField, SingleUVPolynomial, UVPolynomials},
        secret_sharing::SharedValue,
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

    #[test]
    fn check_constants() {
        // check one
        assert_eq!(
            Fp61BitPrime::ONE,
            Fp61BitPrime::ZERO + Fp61BitPrime::truncate_from(1u128)
        );
        // check two inverse
        assert_eq!(
            Fp61BitPrime::INVERSE_OF_TWO * Fp61BitPrime::truncate_from(2u128),
            Fp61BitPrime::ONE
        );
        // check minus one half
        assert_eq!(
            Fp61BitPrime::MINUS_ONE_HALF * Fp61BitPrime::truncate_from(2u128) + Fp61BitPrime::ONE,
            Fp61BitPrime::ZERO
        );
        // check minus two
        assert_eq!(
            Fp61BitPrime::MINUS_TWO * Fp61BitPrime::MINUS_ONE_HALF,
            Fp61BitPrime::ONE
        );
    }

    proptest! {
        #[test]
        fn prop_test_correctness_prover(x_left: bool, x_right: bool, y_left: bool, y_right: bool, prss_left: bool, prss_right: bool){
            correctness_prover_values(x_left, x_right, y_left, y_right, prss_left, prss_right);
        }
    }

    #[allow(clippy::fn_params_excessive_bools)]
    fn correctness_prover_values(
        x_left: bool,
        x_right: bool,
        y_left: bool,
        y_right: bool,
        prss_left: bool,
        prss_right: bool,
    ) {
        let mut array_x_left = BitArray::<[u8; 32]>::ZERO;
        let mut array_x_right = BitArray::<[u8; 32]>::ZERO;
        let mut array_y_left = BitArray::<[u8; 32]>::ZERO;
        let mut array_y_right = BitArray::<[u8; 32]>::ZERO;
        let mut array_prss_left = BitArray::<[u8; 32]>::ZERO;
        let mut array_prss_right = BitArray::<[u8; 32]>::ZERO;

        // initialize bits
        array_x_left.set(0, x_left);
        array_x_right.set(0, x_right);
        array_y_left.set(0, y_left);
        array_y_right.set(0, y_right);
        array_prss_left.set(0, prss_left);
        array_prss_right.set(0, prss_right);

        let prover = Fp61BitPrime::convert_prover(
            &array_x_left,
            &array_x_right,
            &array_y_left,
            &array_y_right,
            &array_prss_right,
        )
        .next()
        .unwrap();

        // compute expected
        // (a,b,c,d,f) = (x_left, y_right, y_left, x_right, prss_right)
        // e = x_left · y_left ⊕ z_left ⊕ prss_left

        // z_left = x_left * y_left ⊕ x_left * y_right ⊕ x_right * y_left ⊕ prss_right ⊕ prss_left
        let z_left =
            (x_left & y_left) ^ (x_left & y_right) ^ (x_right & y_left) ^ prss_right ^ prss_left;

        // ac = x_left * y_left
        let ac = Fp61BitPrime::truncate_from((x_left & y_left).as_u128());
        // (1-e) = (1 - x_left · y_left ⊕ z_left ⊕ prss_left)
        let one_minus_two_e = Fp61BitPrime::ONE
            + Fp61BitPrime::MINUS_TWO
                * Fp61BitPrime::truncate_from((x_left & y_left ^ z_left ^ prss_left).as_u128());
        // g1 = -2ac(1-2e)
        let g1 = Fp61BitPrime::MINUS_TWO * ac * one_minus_two_e;
        // g2=c(1-2e),
        let g2 = Fp61BitPrime::truncate_from(y_left.as_u128()) * one_minus_two_e;
        // g3=a(1-2e),
        let g3 = Fp61BitPrime::truncate_from(x_left) * one_minus_two_e;
        // g4=-1/2(1-2e),
        let g4 = Fp61BitPrime::MINUS_ONE_HALF * one_minus_two_e;
        // bd = y_right * x_right
        let bd = Fp61BitPrime::truncate_from((x_right & y_right).as_u128());
        // (1-2f)
        let one_minus_two_f = Fp61BitPrime::ONE
            + Fp61BitPrime::MINUS_TWO * Fp61BitPrime::truncate_from(prss_right.as_u128());
        // h1=bd(1-2f),
        let h1 = bd * one_minus_two_f;
        // h2=d(1-2f),
        let h2 = Fp61BitPrime::truncate_from(x_right.as_u128()) * one_minus_two_f;
        // h3=b(1-2f),
        let h3 = Fp61BitPrime::truncate_from(y_right) * one_minus_two_f;
        // h4=1-2f,
        let h4 = one_minus_two_f;

        // check expected == computed
        // g polynomial
        assert_eq!(g1, prover.0[0]);
        assert_eq!(g2, prover.0[1]);
        assert_eq!(g3, prover.0[2]);
        assert_eq!(g4, prover.0[3]);

        // h polynomial
        assert_eq!(h1, prover.1[0]);
        assert_eq!(h2, prover.1[1]);
        assert_eq!(h3, prover.1[2]);
        assert_eq!(h4, prover.1[3]);
    }
}
