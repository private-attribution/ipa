use bitvec::{order::Lsb0, view::BitView};

use crate::{
    ff::{Field, Fp61BitPrime, PrimeField},
    protocol::context::dzkp_validator::{Array256Bit, SegmentEntry},
    secret_sharing::{FieldSimd, SharedValue, Vectorizable},
};

// BlockSize is fixed to 32
pub const BLOCK_SIZE: usize = 32;
// UVTupleBlock is a block of interleaved U and V values
pub type UVTupleBlock<F> = ([F; BLOCK_SIZE], [F; BLOCK_SIZE]);

/// Trait for fields compatible with DZKPs
/// Field needs to support conversion to `SegmentEntry`, i.e. `to_segment_entry` which is required by DZKPs
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
    ) -> Vec<UVTupleBlock<Self>>;

    /// This is similar to `convert_prover` except that it is called by the verifier to the left of the prover.
    /// The verifier on the left uses its right shares, since they are consistent with the prover's left shares.
    /// This produces the 'u' values.
    fn convert_value_from_right_prover<'a>(
        x_right: &'a Array256Bit,
        y_right: &'a Array256Bit,
        prss_right: &'a Array256Bit,
        z_right: &'a Array256Bit,
    ) -> Vec<Self>;

    /// This is similar to `convert_prover` except that it is called by the verifier to the right of the prover.
    /// The verifier on the right uses its left shares, since they are consistent with the prover's right shares.
    /// This produces the 'v' values
    fn convert_value_from_left_prover<'a>(
        x_left: &'a Array256Bit,
        y_left: &'a Array256Bit,
        prss_left: &'a Array256Bit,
    ) -> Vec<Self>;
}

impl<const P: usize> FromIterator<Fp61BitPrime> for [Fp61BitPrime; P] {
    fn from_iter<T: IntoIterator<Item = Fp61BitPrime>>(iter: T) -> Self {
        let mut out = [Fp61BitPrime::ZERO; P];
        for (i, elem) in iter.into_iter().enumerate() {
            assert!(
                i < P,
                "Too many elements to collect into array of length {P}",
            );
            out[i] = elem;
        }
        out
    }
}

impl<const P: usize> FromIterator<Fp61BitPrime> for Vec<[Fp61BitPrime; P]> {
    fn from_iter<T: IntoIterator<Item = Fp61BitPrime>>(iter: T) -> Self {
        let mut out = Vec::<[Fp61BitPrime; P]>::new();
        let mut array = [Fp61BitPrime::ZERO; P];
        let mut i = 0usize;
        for elem in iter {
            array[i % P] = elem;
            if (i + 1) % P == 0 {
                out.push(array);
                array = [Fp61BitPrime::ZERO; P];
            }
            i += 1;
        }
        if i % P != 0 {
            out.push(array);
        }
        out
    }
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
    ) -> Vec<UVTupleBlock<Fp61BitPrime>> {
        // precompute ac = a & c = x_left & y_left
        let ac = *x_left & y_left;
        // e = ab⊕cd⊕ f = x_left * y_right ⊕ y_left * x_right ⊕ prss_right
        let e = (*x_left & y_right) ^ (*y_left & x_right) ^ prss_right;
        // precompute bd = b & d = y_right & x_right
        let bd = *y_right & x_right;

        x_left
            .data
            .iter()
            .zip(y_right.data.iter())
            .zip(y_left.data.iter())
            .zip(x_right.data.iter())
            .zip(prss_right.data.iter())
            .zip(ac.data.iter())
            .zip(e.data.iter())
            .zip(bd.data.iter())
            .map(|(((((((a, b), c), d), f), ac), e), bd)| {
                (
                    // g polynomial
                    a.view_bits::<Lsb0>()
                        .iter()
                        .zip(c.view_bits::<Lsb0>().iter())
                        .zip(e.view_bits::<Lsb0>().iter())
                        .zip(ac.view_bits::<Lsb0>().iter())
                        .flat_map(|(((a, c), e), ac)| {
                            let one_minus_two_e = Fp61BitPrime::ONE
                                + Fp61BitPrime::MINUS_TWO.specialized_mul(Fp61BitPrime::from_bit(*e));
                            [
                                // g1=-2ac(1-2e),
                                Fp61BitPrime::MINUS_TWO.specialized_mul(
                                    Fp61BitPrime::from_bit(*ac)).specialized_mul(
                                    one_minus_two_e),
                                // g2=c(1-2e),
                                Fp61BitPrime::from_bit(*c).specialized_mul(one_minus_two_e),
                                // g3=a(1-2e),
                                Fp61BitPrime::from_bit(*a).specialized_mul(one_minus_two_e),
                                // g4=-1/2(1-2e),
                                Fp61BitPrime::MINUS_ONE_HALF.specialized_mul(one_minus_two_e),
                            ]
                        })
                        .collect::<[Fp61BitPrime; BLOCK_SIZE]>(),
                    // h polynomial
                    b.view_bits::<Lsb0>()
                        .iter()
                        .zip(d.view_bits::<Lsb0>().iter())
                        .zip(f.view_bits::<Lsb0>().iter())
                        .zip(bd.view_bits::<Lsb0>().iter())
                        .flat_map(|(((b, d), f), bd)| {
                            let one_minus_two_f = Fp61BitPrime::ONE
                                + Fp61BitPrime::MINUS_TWO.specialized_mul(Fp61BitPrime::from_bit(*f));
                            [
                                // h1=bd(1-2f),
                                Fp61BitPrime::from_bit(*bd).specialized_mul(one_minus_two_f),
                                // h2=d(1-2f),
                                Fp61BitPrime::from_bit(*d).specialized_mul(one_minus_two_f),
                                // h3=b(1-2f),
                                Fp61BitPrime::from_bit(*b).specialized_mul(one_minus_two_f),
                                // h4=1-2f,
                                one_minus_two_f,
                            ]
                        })
                        .collect::<[Fp61BitPrime; BLOCK_SIZE]>(),
                )
            })
            .collect::<Vec<_>>()
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
    fn convert_value_from_right_prover<'a>(
        x_right: &'a Array256Bit,
        y_right: &'a Array256Bit,
        prss_right: &'a Array256Bit,
        z_right: &'a Array256Bit,
    ) -> Vec<Self> {
        // precompute ac = a & c = x_right & y_right
        let ac = *x_right & y_right;
        // e = ac ⊕ zright ⊕ prssright
        // as defined in the paper
        let e = ac ^ prss_right ^ z_right;
        x_right
            .data
            .iter()
            .zip(y_right.data.iter())
            .zip(ac.data.iter())
            .zip(e.data.iter())
            .flat_map(|(((a, c), ac), e)| {
                // g polynomial
                a.view_bits::<Lsb0>()
                    .iter()
                    .zip(c.view_bits::<Lsb0>().iter())
                    .zip(e.view_bits::<Lsb0>().iter())
                    .zip(ac.view_bits::<Lsb0>().iter())
                    .flat_map(|(((a, c), e), ac)| {
                        let one_minus_two_e = Fp61BitPrime::ONE
                            + Fp61BitPrime::MINUS_TWO.specialized_mul(Fp61BitPrime::from_bit(*e));
                        [
                            // g1=-2ac(1-2e),
                            Fp61BitPrime::MINUS_TWO.specialized_mul(Fp61BitPrime::from_bit(*ac)).specialized_mul(one_minus_two_e),
                            // g2=c(1-2e),
                            Fp61BitPrime::from_bit(*c).specialized_mul(one_minus_two_e),
                            // g3=a(1-2e),
                            Fp61BitPrime::from_bit(*a).specialized_mul(one_minus_two_e),
                            // g4=-1/2(1-2e),
                            Fp61BitPrime::MINUS_ONE_HALF.specialized_mul(one_minus_two_e),
                        ]
                    })
            })
            .collect::<Vec<Fp61BitPrime>>()
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
    fn convert_value_from_left_prover<'a>(
        x_left: &'a Array256Bit,
        y_left: &'a Array256Bit,
        prss_left: &'a Array256Bit,
    ) -> Vec<Self> {
        // precompute bd = b & d = y_left & x_left
        let bd = *y_left & x_left;
        y_left
            .data
            .iter()
            .zip(x_left.data.iter())
            .zip(prss_left.data.iter())
            .zip(bd.data.iter())
            .flat_map(|(((b, d), f), bd)| {
                // h polynomial
                b.view_bits::<Lsb0>()
                    .iter()
                    .zip(d.view_bits::<Lsb0>().iter())
                    .zip(f.view_bits::<Lsb0>().iter())
                    .zip(bd.view_bits::<Lsb0>().iter())
                    .flat_map(|(((b, d), f), bd)| {
                        let one_minus_two_f = Fp61BitPrime::ONE
                            + Fp61BitPrime::MINUS_TWO.specialized_mul(Fp61BitPrime::from_bit(*f));
                        [
                            // h1=bd(1-2f),
                            Fp61BitPrime::from_bit(*bd).specialized_mul(one_minus_two_f),
                            // h2=d(1-2f),
                            Fp61BitPrime::from_bit(*d).specialized_mul(one_minus_two_f),
                            // h3=b(1-2f),
                            Fp61BitPrime::from_bit(*b).specialized_mul(one_minus_two_f),
                            // h4=1-2f,
                            one_minus_two_f,
                        ]
                    })
            })
            .collect::<Vec<Fp61BitPrime>>()
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use bitvec::{array::BitArray, macros::internal::funty::Fundamental, slice::BitSlice};
    use proptest::proptest;
    use rand::{thread_rng, Rng};

    use crate::{
        ff::{Field, Fp61BitPrime, U128Conversions},
        protocol::context::dzkp_field::{DZKPBaseField, UVTupleBlock, BLOCK_SIZE},
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
            Fp61BitPrime::convert_value_from_right_prover(&x_left, &y_left, &prss_left, &z_right),
            // flip intputs right to left since it is checked against itself and not party on the left
            Fp61BitPrime::convert_value_from_left_prover(&x_right, &y_right, &prss_right),
        );
    }
    fn assert_convert<P, L, R>(prover: P, verifier_left: L, verifier_right: R)
    where
        P: IntoIterator<Item = UVTupleBlock<Fp61BitPrime>>,
        L: IntoIterator<Item = Fp61BitPrime>,
        R: IntoIterator<Item = Fp61BitPrime>,
    {
        prover
            .into_iter()
            .zip(
                verifier_left
                    .into_iter()
                    .collect::<Vec<[Fp61BitPrime; BLOCK_SIZE]>>(),
            )
            .zip(
                verifier_right
                    .into_iter()
                    .collect::<Vec<[Fp61BitPrime; BLOCK_SIZE]>>(),
            )
            .for_each(|((prover, verifier_left), verifier_right)| {
                assert_eq!(prover.0, verifier_left);
                assert_eq!(prover.1, verifier_right);
            });
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
        )[0];

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
