use std::{ops::Index, sync::LazyLock};

use bitvec::field::BitField;

use crate::{
    ff::{Field, Fp61BitPrime, PrimeField},
    protocol::context::dzkp_validator::{Array256Bit, MultiplicationInputsBlock, SegmentEntry},
    secret_sharing::{FieldSimd, SharedValue, Vectorizable},
};

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
}

impl DZKPBaseField for Fp61BitPrime {
    const INVERSE_OF_TWO: Self = Fp61BitPrime::const_truncate(1_152_921_504_606_846_976u64);
    const MINUS_ONE_HALF: Self = Fp61BitPrime::const_truncate(1_152_921_504_606_846_975u64);
    const MINUS_TWO: Self = Fp61BitPrime::const_truncate(2_305_843_009_213_693_949u64);
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

/// Construct indices for the `TABLE_U` and `TABLE_V` lookup tables.
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
fn bits_to_table_indices(b0: u128, b1: u128, b2: u128) -> [u128; 4] {
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

pub struct UVTable<F>(pub [[F; 4]; 8]);

impl<F> Index<u8> for UVTable<F> {
    type Output = [F; 4];

    fn index(&self, index: u8) -> &Self::Output {
        self.0.index(usize::from(index))
    }
}

impl<F> Index<usize> for UVTable<F> {
    type Output = [F; 4];

    fn index(&self, index: usize) -> &Self::Output {
        self.0.index(index)
    }
}

// Table used for `convert_prover` and `convert_value_from_right_prover`.
//
// This table is for "g" or "u" values. This table is "right" on a verifier when it is
// processing values for the prover on its right. On a prover, this table is "left".
//
// The conversion logic is from https://eprint.iacr.org/2023/909.pdf.
pub static TABLE_U: LazyLock<UVTable<Fp61BitPrime>> = LazyLock::new(|| {
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
    UVTable(result.try_into().unwrap())
});

// Table used for `convert_prover` and `convert_value_from_left_prover`.
//
// This table is for "h" or "v" values. This table is "left" on a verifier when it is
// processing values for the prover on its left. On a prover, this table is "right".
//
// The conversion logic is from https://eprint.iacr.org/2023/909.pdf.
pub static TABLE_V: LazyLock<UVTable<Fp61BitPrime>> = LazyLock::new(|| {
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
    UVTable(result.try_into().unwrap())
});

/// Lookup-table-based conversion logic used by `table_indices_prover`,
/// `table_indices_from_right_prover`, and `table_indices_from_left_prover`.
///
/// Inputs `i0`, `i1`, and `i2` each contain the value of one of the "a" through "f"
/// intermediates for each of 256 multiplies. `table` is the lookup table to use,
/// which should be either `TABLE_U` or `TABLE_V`.
///
/// We want to interpret the 3-tuple of intermediates at each bit position in `i0`, `i1`
/// and `i2` as an integer index in the range 0..8 into the table. The
/// `bits_to_table_indices` helper does this in bulk more efficiently than using
/// bit-manipulation to handle them one-by-one.
///
/// Preserving the order from inputs to outputs is not necessary for correctness as long
/// as the same order is used on all three helpers. We preserve the order anyways
/// to simplify the end-to-end dataflow, even though it makes this routine slightly
/// more complicated.
#[allow(clippy::missing_panics_doc)]
fn intermediates_to_table_indices<'a>(
    i0: &Array256Bit,
    i1: &Array256Bit,
    i2: &Array256Bit,
    mut out: impl Iterator<Item = &'a mut u8>,
) {
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
    let [mut z00, mut z01, mut z02, mut z03] = bits_to_table_indices(i00, i10, i20);
    let [mut z10, mut z11, mut z12, mut z13] = bits_to_table_indices(i01, i11, i21);

    #[allow(clippy::cast_possible_truncation)]
    for _ in 0..32 {
        // Take one index in turn from each `z` to preserve the output order.
        *out.next().unwrap() = (z00 as u8) & 0x7;
        z00 >>= 4;
        *out.next().unwrap() = (z01 as u8) & 0x7;
        z01 >>= 4;
        *out.next().unwrap() = (z02 as u8) & 0x7;
        z02 >>= 4;
        *out.next().unwrap() = (z03 as u8) & 0x7;
        z03 >>= 4;
    }
    #[allow(clippy::cast_possible_truncation)]
    for _ in 0..32 {
        *out.next().unwrap() = (z10 as u8) & 0x7;
        z10 >>= 4;
        *out.next().unwrap() = (z11 as u8) & 0x7;
        z11 >>= 4;
        *out.next().unwrap() = (z12 as u8) & 0x7;
        z12 >>= 4;
        *out.next().unwrap() = (z13 as u8) & 0x7;
        z13 >>= 4;
    }
    debug_assert!(out.next().is_none());
}

impl MultiplicationInputsBlock {
    /// Repack the intermediates in this block into lookup indices for `TABLE_U` and `TABLE_V`.
    ///
    /// This is the convert function called by the prover.
    //
    // We use the conversion logic from https://eprint.iacr.org/2023/909.pdf
    //
    // Prover and left compute:
    // g1=-2ac(1-2e),
    // g2=c(1-2e),
    // g3=a(1-2e),
    // g4=-1/2(1-2e),
    //
    // Prover and right compute:
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
    #[must_use]
    pub fn table_indices_prover(&self) -> Vec<(u8, u8)> {
        let a = &self.x_left;
        let b = &self.y_right;
        let c = &self.y_left;
        let d = &self.x_right;
        // e = ab ⊕ cd ⊕ f = x_left * y_right ⊕ y_left * x_right ⊕ prss_right
        let e = (self.x_left & self.y_right) ^ (self.y_left & self.x_right) ^ self.prss_right;
        let f = &self.prss_right;

        let mut output = vec![(0u8, 0u8); 256];
        intermediates_to_table_indices(a, c, &e, output.iter_mut().map(|tup| &mut tup.0));
        intermediates_to_table_indices(b, d, f, output.iter_mut().map(|tup| &mut tup.1));
        output
    }

    /// Repack the intermediates in this block into lookup indices for `TABLE_U`.
    ///
    /// This is the convert function called by the verifier when processing for the
    /// prover on its right.
    //
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
    #[must_use]
    pub fn table_indices_from_right_prover(&self) -> Vec<u8> {
        let a = &self.x_right;
        let c = &self.y_right;
        // e = ac ⊕ zright ⊕ prssright
        // as defined in the paper
        let e = (self.x_right & self.y_right) ^ self.prss_right ^ self.z_right;

        let mut output = vec![0u8; 256];
        intermediates_to_table_indices(a, c, &e, output.iter_mut());
        output
    }

    /// Repack the intermediates in this block into lookup indices for `TABLE_V`.
    ///
    /// This is the convert function called by the verifier when processing for the
    /// prover on its left.
    //
    // We use the conversion logic from https://eprint.iacr.org/2023/909.pdf
    //
    // The prover and the verifier on its left compute:
    // h1=bd(1-2f),
    // h2=d(1-2f),
    // h3=b(1-2f),
    // h4=1-2f,
    //
    // where
    // (b,d,f) = (y_left, x_left, prss_left)
    #[must_use]
    pub fn table_indices_from_left_prover(&self) -> Vec<u8> {
        let b = &self.y_left;
        let d = &self.x_left;
        let f = &self.prss_left;

        let mut output = vec![0u8; 256];
        intermediates_to_table_indices(b, d, f, output.iter_mut());
        output
    }
}

#[cfg(all(test, unit_test))]
pub mod tests {

    use bitvec::{array::BitArray, macros::internal::funty::Fundamental};
    use proptest::proptest;
    use rand::{thread_rng, Rng};

    use crate::{
        ff::{Field, Fp61BitPrime, U128Conversions},
        protocol::context::{
            dzkp_field::{bits_to_table_indices, DZKPBaseField, TABLE_U, TABLE_V},
            dzkp_validator::MultiplicationInputsBlock,
        },
        secret_sharing::SharedValue,
        test_executor::run_random,
    };

    #[test]
    fn table_indices() {
        let b0 = 0xaa;
        let b1 = 0xcc;
        let b2 = 0xf0;
        let [z0, z1, z2, z3] = bits_to_table_indices(b0, b1, b2);
        assert_eq!(z0, 0x40_u128);
        assert_eq!(z1, 0x51_u128);
        assert_eq!(z2, 0x62_u128);
        assert_eq!(z3, 0x73_u128);

        let mut rng = thread_rng();
        let b0 = rng.gen();
        let b1 = rng.gen();
        let b2 = rng.gen();
        let [z0, z1, z2, z3] = bits_to_table_indices(b0, b1, b2);

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

    impl MultiplicationInputsBlock {
        /// Rotate the "right" values into the "left" values, setting the right values
        /// to zero. If the input represents a prover's block of intermediates, the
        /// output represents the intermediates that the verifier on the prover's right
        /// shares with it.
        #[must_use]
        pub fn rotate_left(&self) -> Self {
            Self {
                x_left: self.x_right,
                y_left: self.y_right,
                prss_left: self.prss_right,
                x_right: [0u8; 32].into(),
                y_right: [0u8; 32].into(),
                prss_right: [0u8; 32].into(),
                z_right: [0u8; 32].into(),
            }
        }

        /// Rotate the "left" values into the "right" values, setting the left values to
        /// zero. `z_right` is calculated to be consistent with the other values. If the
        /// input represents a prover's block of intermediates, the output represents
        /// the intermediates that the verifier on the prover's left shares with it.
        #[must_use]
        pub fn rotate_right(&self) -> Self {
            let z_right = (self.x_left & self.y_left)
                ^ (self.x_left & self.y_right)
                ^ (self.x_right & self.y_left)
                ^ self.prss_left
                ^ self.prss_right;

            Self {
                x_right: self.x_left,
                y_right: self.y_left,
                prss_right: self.prss_left,
                x_left: [0u8; 32].into(),
                y_left: [0u8; 32].into(),
                prss_left: [0u8; 32].into(),
                z_right,
            }
        }
    }

    #[test]
    fn batch_convert() {
        run_random(|mut rng| async move {
            let block = rng.gen::<MultiplicationInputsBlock>();

            // When verifying, we rotate the intermediates to match what each prover
            // would have. `rotate_right` also calculates z_right from the others.
            assert_convert(
                block.table_indices_prover(),
                block.rotate_right().table_indices_from_right_prover(),
                block.rotate_left().table_indices_from_left_prover(),
            );
        });
    }

    fn assert_convert<P, L, R>(prover: P, verifier_left: L, verifier_right: R)
    where
        P: IntoIterator<Item = (u8, u8)>,
        L: IntoIterator<Item = u8>,
        R: IntoIterator<Item = u8>,
    {
        prover
            .into_iter()
            .zip(verifier_left.into_iter().collect::<Vec<_>>())
            .zip(verifier_right.into_iter().collect::<Vec<_>>())
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
    #[must_use]
    pub fn reference_convert(
        x_left: bool,
        x_right: bool,
        y_left: bool,
        y_right: bool,
        prss_left: bool,
        prss_right: bool,
    ) -> ([Fp61BitPrime; 4], [Fp61BitPrime; 4]) {
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

        ([g1, g2, g3, g4], [h1, h2, h3, h4])
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

        let block = MultiplicationInputsBlock {
            x_left: array_x_left,
            x_right: array_x_right,
            y_left: array_y_left,
            y_right: array_y_right,
            prss_left: array_prss_left,
            prss_right: array_prss_right,
            z_right: BitArray::ZERO,
        };

        let prover = block.table_indices_prover()[0];

        let ([g1, g2, g3, g4], [h1, h2, h3, h4]) =
            reference_convert(x_left, x_right, y_left, y_right, prss_left, prss_right);

        // check expected == computed
        // g polynomial
        assert_eq!(g1, TABLE_U[prover.0][0]);
        assert_eq!(g2, TABLE_U[prover.0][1]);
        assert_eq!(g3, TABLE_U[prover.0][2]);
        assert_eq!(g4, TABLE_U[prover.0][3]);

        // h polynomial
        assert_eq!(h1, TABLE_V[prover.1][0]);
        assert_eq!(h2, TABLE_V[prover.1][1]);
        assert_eq!(h3, TABLE_V[prover.1][2]);
        assert_eq!(h4, TABLE_V[prover.1][3]);
    }
}
