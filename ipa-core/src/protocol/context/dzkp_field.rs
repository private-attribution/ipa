use std::{iter::zip, sync::LazyLock};

use bitvec::field::BitField;

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

/// Construct indices for the `convert_values` lookup tables.
///
/// `b0` has the least significant bit of each index, and `b1` and `b2` the subsequent
/// bits. This routine rearranges the bits so that there is one table index in each
/// nibble of the output. The technique is similar to the matrix transposes in
/// `secret_sharing::vector::transpose`, which are based on a technique in chapter 7
/// of "Hacker's Delight" (2nd ed.).
///
/// Output word `j` contains the table indices for input positions `i` having
/// (i%4) == j. The "0s", "1s", "2s", "3s" comments trace the movement from
/// input to output.
#[must_use]
fn convert_values_table_indices(b0: u128, b1: u128, b2: u128) -> [u128; 4] {
    // 0x55 is 0b0101_0101. This mask selects bits having (i%2) == 0.
    const CONST_55: u128 = u128::from_le_bytes([0x55; 16]);
    // 0xaa is 0b1010_1010. This mask selects bits having (i%2) == 1.
    const CONST_AA: u128 = u128::from_le_bytes([0xaa; 16]);

    // 0x33 is 0b0011_0011. This mask selects bits having (i%4) ∈ {0,1}.
    const CONST_33: u128 = u128::from_le_bytes([0x33; 16]);
    // 0xcc is 0b1100_1100. This mask selects bits having (i%4) ∈ {2,3}.
    const CONST_CC: u128 = u128::from_le_bytes([0xcc; 16]);

    // `k` = keep, `s` = swap
    let b0k = b0 & CONST_55;
    let b0s = b0 & CONST_AA;
    let b1s = b1 & CONST_55;
    let b1k = b1 & CONST_AA;
    let b2k = b2 & CONST_55;
    let b2s = b2 & CONST_AA;

    // Swap the bits having (i%2) == 1 in b0/b2 with the bits having (i%2) == 0 in
    // b1/b3, so that `c0` and `c1` have the lower halves of each index, and `c2` and
    // `c3` have the upper halves of each index. (b3 is implicitly zero.)
    let c0 = b0k | (b1s << 1); // 0s and 2s
    let c1 = b1k | (b0s >> 1); // 1s and 3s
    let c2 = b2k;
    let c3 = b2s >> 1;

    let c0k = c0 & CONST_33; // 0s
    let c0s = c0 & CONST_CC; // 2s
    let c1k = c1 & CONST_33; // 1s
    let c1s = c1 & CONST_CC; // 3s
    let c2s = c2 & CONST_33;
    let c2k = c2 & CONST_CC;
    let c3s = c3 & CONST_33;
    let c3k = c3 & CONST_CC;

    // Swap the bits having (i%4) ∈ {2,3} in c0/c1 with the bits having (i%4) ∈ {0,1} in
    // c2/c3.
    let y0 = c0k | (c2s << 2); // 0s
    let y1 = c1k | (c3s << 2); // 1s
    let y2 = c2k | (c0s >> 2); // 2s
    let y3 = c3k | (c1s >> 2); // 3s

    [y0, y1, y2, y3]
}

// Table used for `convert_prover` and `convert_value_from_right_prover`.
//
// The conversion to "g" and "h" values is from https://eprint.iacr.org/2023/909.pdf.
static TABLE_RIGHT: LazyLock<[[Fp61BitPrime; 4]; 8]> = LazyLock::new(|| {
    let mut result = Vec::with_capacity(8);
    for e in [false, true] {
        for c in [false, true] {
            for a in [false, true] {
                let ac = a & c;
                let one_minus_two_e =
                    Fp61BitPrime::ONE + Fp61BitPrime::MINUS_TWO * Fp61BitPrime::from_bit(e);
                result.push([
                    // g1=-2ac(1-2e),
                    Fp61BitPrime::MINUS_TWO * Fp61BitPrime::from_bit(ac) * one_minus_two_e,
                    // g2=c(1-2e),
                    Fp61BitPrime::from_bit(c) * one_minus_two_e,
                    // g3=a(1-2e),
                    Fp61BitPrime::from_bit(a) * one_minus_two_e,
                    // g4=-1/2(1-2e),
                    Fp61BitPrime::MINUS_ONE_HALF * one_minus_two_e,
                ]);
            }
        }
    }
    result.try_into().unwrap()
});

// Table used for `convert_prover` and `convert_value_from_left_prover`.
//
// The conversion to "g" and "h" values is from https://eprint.iacr.org/2023/909.pdf.
static TABLE_LEFT: LazyLock<[[Fp61BitPrime; 4]; 8]> = LazyLock::new(|| {
    let mut result = Vec::with_capacity(8);
    for f in [false, true] {
        for d in [false, true] {
            for b in [false, true] {
                let bd = b & d;
                let one_minus_two_f =
                    Fp61BitPrime::ONE + Fp61BitPrime::MINUS_TWO * Fp61BitPrime::from_bit(f);
                result.push([
                    // h1=bd(1-2f),
                    Fp61BitPrime::from_bit(bd) * one_minus_two_f,
                    // h2=d(1-2f),
                    Fp61BitPrime::from_bit(d) * one_minus_two_f,
                    // h3=b(1-2f),
                    Fp61BitPrime::from_bit(b) * one_minus_two_f,
                    // h4=1-2f,
                    one_minus_two_f,
                ]);
            }
        }
    }
    result.try_into().unwrap()
});

/// Lookup-table-based conversion logic used by `convert_prover`,
/// `convert_value_from_left_prover`, and `convert_value_from_left_prover`.
///
/// Inputs `i0`, `i1`, and `i2` each contain the value of one of the "a" through "f"
/// intermediates for each of 256 multiplies. `table` is the lookup table to use,
/// which should be either `TABLE_LEFT` or `TABLE_RIGHT`.
///
/// We want to interpret the 3-tuple of intermediates at each bit position in `i0`, `i1`
/// and `i2` as an integer index in the range 0..8 into the table. The
/// `convert_values_table_indices` helper does this in bulk more efficiently than using
/// bit-manipulation to handle them one-by-one.
///
/// Preserving the order from inputs to outputs is not necessary for correctness as long
/// as the same order is used on all three helpers. We preserve the order anyways
/// to simplify the end-to-end dataflow, even though it makes this routine slightly
/// more complicated.
fn convert_values(
    i0: &Array256Bit,
    i1: &Array256Bit,
    i2: &Array256Bit,
    table: &[[Fp61BitPrime; 4]; 8],
) -> Vec<Fp61BitPrime> {
    // Split inputs to two `u128`s. We do this because `u128` is the largest integer
    // type rust supports. It is possible that using SIMD types here would improve
    // code generation for AVX-256/512.
    let i00 = i0[..128].load_le::<u128>();
    let i01 = i0[128..].load_le::<u128>();

    let i10 = i1[..128].load_le::<u128>();
    let i11 = i1[128..].load_le::<u128>();

    let i20 = i2[..128].load_le::<u128>();
    let i21 = i2[128..].load_le::<u128>();

    // Output word `j` in each set contains the table indices for input positions `i`
    // having (i%4) == j.
    let [mut z00, mut z01, mut z02, mut z03] = convert_values_table_indices(i00, i10, i20);
    let [mut z10, mut z11, mut z12, mut z13] = convert_values_table_indices(i01, i11, i21);

    let mut result = Vec::with_capacity(1024);
    for _ in 0..32 {
        // Take one index in turn from each `z` to preserve the output order.
        for z in [&mut z00, &mut z01, &mut z02, &mut z03] {
            result.extend(table[(*z as usize) & 0x7]);
            *z >>= 4;
        }
    }
    for _ in 0..32 {
        for z in [&mut z10, &mut z11, &mut z12, &mut z13] {
            result.extend(table[(*z as usize) & 0x7]);
            *z >>= 4;
        }
    }
    debug_assert!(result.len() == 1024);

    result
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
    #[allow(clippy::many_single_char_names)]
    fn convert_prover<'a>(
        x_left: &'a Array256Bit,
        x_right: &'a Array256Bit,
        y_left: &'a Array256Bit,
        y_right: &'a Array256Bit,
        prss_right: &'a Array256Bit,
    ) -> Vec<UVTupleBlock<Fp61BitPrime>> {
        let a = x_left;
        let b = y_right;
        let c = y_left;
        let d = x_right;
        // e = ab ⊕ cd ⊕ f = x_left * y_right ⊕ y_left * x_right ⊕ prss_right
        let e = (*x_left & y_right) ^ (*y_left & x_right) ^ prss_right;
        let f = prss_right;

        let g = convert_values(a, c, &e, &TABLE_RIGHT);
        let h = convert_values(b, d, f, &TABLE_LEFT);

        zip(g.chunks_exact(BLOCK_SIZE), h.chunks_exact(BLOCK_SIZE))
            .map(|(g_chunk, h_chunk)| (g_chunk.try_into().unwrap(), h_chunk.try_into().unwrap()))
            .collect()
    }

    // Convert allows to convert individual bits from multiplication gates into dzkp compatible field elements
    // We use the conversion logic from https://eprint.iacr.org/2023/909.pdf
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
        let a = x_right;
        let c = y_right;
        // e = ac ⊕ zright ⊕ prssright
        // as defined in the paper
        let e = (*a & *c) ^ prss_right ^ z_right;

        convert_values(a, c, &e, &TABLE_RIGHT)
    }

    // Convert allows to convert individual bits from multiplication gates into dzkp compatible field elements
    // We use the conversion logic from https://eprint.iacr.org/2023/909.pdf
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
        let b = y_left;
        let d = x_left;
        let f = prss_left;

        convert_values(b, d, f, &TABLE_LEFT)
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use bitvec::{array::BitArray, macros::internal::funty::Fundamental, slice::BitSlice};
    use proptest::proptest;
    use rand::{thread_rng, Rng};

    use crate::{
        ff::{Field, Fp61BitPrime, U128Conversions},
        protocol::context::dzkp_field::{
            convert_values_table_indices, DZKPBaseField, UVTupleBlock, BLOCK_SIZE,
        },
        secret_sharing::SharedValue,
    };

    #[test]
    fn table_indices() {
        let b0 = 0xaa;
        let b1 = 0xcc;
        let b2 = 0xf0;
        let [z0, z1, z2, z3] = convert_values_table_indices(b0, b1, b2);
        assert_eq!(z0, 0x40_u128);
        assert_eq!(z1, 0x51_u128);
        assert_eq!(z2, 0x62_u128);
        assert_eq!(z3, 0x73_u128);

        let mut rng = thread_rng();
        let b0 = rng.gen();
        let b1 = rng.gen();
        let b2 = rng.gen();
        let [z0, z1, z2, z3] = convert_values_table_indices(b0, b1, b2);

        for i in (0..128).step_by(4) {
            fn check(i: u32, j: u32, b0: u128, b1: u128, b2: u128, z: u128) {
                let bit0 = (b0 >> j) & 1_u128;
                let bit1 = (b1 >> j) & 1_u128;
                let bit2 = (b2 >> j) & 1_u128;
                let expected = bit2 << 2 | bit1 << 1 | bit0;
                let actual = (z >> i) & 0xf;
                assert_eq!(
                    actual, expected,
                    "expected index {i} to be {expected}, but got {actual}",
                );
            }
            check(i, i, b0, b1, b2, z0);
            check(i, i + 1, b0, b1, b2, z1);
            check(i, i + 2, b0, b1, b2, z2);
            check(i, i + 3, b0, b1, b2, z3);
        }
    }

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
