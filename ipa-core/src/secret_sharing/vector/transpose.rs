//! Bit matrix transpose operations.
//!
//! These are used to convert data to and from vectorized representation.
//!
//! For example, if there is a 32-bit value associated with each record, the natural storage
//! representation for those values is something like a `Vec<BA32>`, with the vector indexed by
//! records.
//!
//! In vectorized code, we instead want to use something like `BitDecomposed<BA16>`, where each
//! `BA16` holds the value of a particular bit for each of 16 records, and the `BitDecomposed`
//! (which is just a wrapper around a `Vec`) is indexed by bits.
//!
//! To convert between these representations we need to transpose a 16x32 bit matrix into a 32x16
//! bit matrix.
//!
//! This module stores bytes and bits are in little-endian order. Less significant bytes store data
//! closer to the top or left of the matrix. Within each byte, the first (leftmost) column is in
//! the least significant bit, and the last (rightmost) column is in the most significant bit.
//!
//! These implementations are somewhat optimized; it is certainly possible to optimize further, but
//! that is only worthwhile if profiling indicates this is a significant contributor to our overall
//! performance. Also, for some functions, the generated code is much better with `codegen-units =
//! 1` than with the default codegen-units (unfortunately, `codegen-units = 1` significantly
//! increases compile time). See [rust issue 47745](https://github.com/rust-lang/rust/issues/47745).
//!
//! Some possibilities for further optimization:
//!  * Use codegen-units = 1 or figure out how to get comparable codegen without it.
//!  * Avoid cost of zero-initializing the transpose destination.
//!  * Use Rust's portable SIMD abstraction (not yet stable as of early 2024), or code directly
//!    against platform SIMD intrinsics.
//!
//! For more ideas on optimizing bit matrix transposes in rust, see:
//!  * <https://stackoverflow.com/a/77596340>
//!  * <https://github.com/swenson/binary_matrix/tree/simd-transpose>

// This rule throws false positives on "MxN".
#![allow(clippy::doc_markdown)]

#[cfg(any(all(test, unit_test), feature = "enable-benches"))]
use std::borrow::Borrow;
use std::{array, convert::Infallible};

use crate::{
    error::{LengthError, UnwrapInfallible},
    ff::{
        boolean::Boolean,
        boolean_array::{BA16, BA256, BA64},
    },
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
        BitDecomposed, SharedValue, StdArray,
    },
};

/// Trait for overwriting a value with the transpose of a source value.
pub trait TransposeFrom<T> {
    type Error;

    /// Overwrite `self` with the transpose of `src`.
    ///
    /// # Errors
    /// If the size of the source and destination are not compatible.
    fn transpose_from(&mut self, src: T) -> Result<(), Self::Error>;

    /// Fills a new `Self` with the transpose of `src`.
    ///
    /// # Errors
    /// If the size of the source and destination are not compatible.
    fn transposed_from(src: T) -> Result<Self, Self::Error>
    where
        Self: Default,
    {
        let mut dst = Self::default();
        dst.transpose_from(src)?;
        Ok(dst)
    }
}

/// 8x8 bit matrix transpose.
//
// From Hacker's Delight (2nd edition), Figure 7-6.
#[cfg(any(all(test, unit_test), feature = "enable-benches"))]
#[inline]
pub fn transpose_8x8<B: Borrow<[u8; 8]>>(x: B) -> [u8; 8] {
    let mut x = u64::from_le_bytes(*x.borrow());

    x = x & 0xaa55_aa55_aa55_aa55
        | (x & 0x00aa_00aa_00aa_00aa) << 7
        | (x >> 7) & 0x00aa_00aa_00aa_00aa;

    x = x & 0xcccc_3333_cccc_3333
        | (x & 0x0000_cccc_0000_cccc) << 14
        | (x >> 14) & 0x0000_cccc_0000_cccc;

    x = x & 0xf0f0_f0f0_0f0f_0f0f
        | (x & 0x0000_0000_f0f0_f0f0) << 28
        | (x >> 28) & 0x0000_0000_f0f0_f0f0;

    x.to_le_bytes()
}

/// 16x16 bit matrix transpose.
//
// Loosely based on Hacker's Delight (2nd edition), Figure 7-6.
#[inline]
pub fn transpose_16x16(src: &[u8; 32]) -> [u8; 32] {
    let x: [u64; 4] =
        array::from_fn(|i| u64::from_le_bytes(src[8 * i..8 * (i + 1)].try_into().unwrap()));

    let mut y0 = [0u64; 4];
    let s0 = 15;
    let mut y1 = [0u64; 4];
    let s1 = 30;
    for i in 0..4 {
        y0[i] = x[i] & 0xaaaa_5555_aaaa_5555
            | (x[i] & 0x0000_aaaa_0000_aaaa) << s0
            | (x[i] >> s0) & 0x0000_aaaa_0000_aaaa;

        y1[i] = y0[i] & 0xcccc_cccc_3333_3333
            | (y0[i] & 0x0000_0000_cccc_cccc) << s1
            | (y0[i] >> s1) & 0x0000_0000_cccc_cccc;
    }

    let y1_swp = [y1[1], y1[0], y1[3], y1[2]];
    let m2a = [
        0x0f0f_0f0f_0f0f_0f0f,
        0xf0f0_f0f0_f0f0_f0f0,
        0x0f0f_0f0f_0f0f_0f0f,
        0xf0f0_f0f0_f0f0_f0f0,
    ];
    let m2b = [0xf0f0_f0f0_f0f0_f0f0, 0, 0xf0f0_f0f0_f0f0_f0f0, 0];
    let m2c = [0, 0xf0f0_f0f0_f0f0_f0f0, 0, 0xf0f0_f0f0_f0f0_f0f0];
    let s2 = 4;
    let mut y2 = [0u64; 4];
    for i in 0..4 {
        y2[i] = y1[i] & m2a[i] | (y1_swp[i] << s2) & m2b[i] | (y1_swp[i] & m2c[i]) >> s2;
    }

    let mut y3 = [0u64; 4];
    for i in 0..2 {
        y3[i] = y2[i] & 0x00ff_00ff_00ff_00ff | (y2[i + 2] & 0x00ff_00ff_00ff_00ff) << 8;
    }
    for i in 0..2 {
        y3[i + 2] = (y2[i] & 0xff00_ff00_ff00_ff00) >> 8 | y2[i + 2] & 0xff00_ff00_ff00_ff00;
    }

    let mut dst = [0u8; 32];
    for i in 0..4 {
        *<&mut [u8; 8] as TryFrom<&mut [u8]>>::try_from(&mut dst[8 * i..8 * (i + 1)]).unwrap() =
            y3[i].to_le_bytes();
    }
    dst
}

// Degenerate transposes.

impl TransposeFrom<AdditiveShare<BA256, 1>> for Vec<AdditiveShare<BA256>> {
    type Error = Infallible;

    fn transpose_from(&mut self, src: AdditiveShare<BA256, 1>) -> Result<(), Infallible> {
        *self = vec![src];
        Ok(())
    }
}

impl TransposeFrom<Vec<StdArray<Boolean, 1>>> for Vec<BA256> {
    type Error = Infallible;

    fn transpose_from(&mut self, src: Vec<StdArray<Boolean, 1>>) -> Result<(), Infallible> {
        *self = vec![src.iter().map(Boolean::from_array).collect::<BA256>()];
        Ok(())
    }
}

/// Perform a larger transpose using an 16x16 kernel.
///
/// Matrix height and width must be multiples of 16.
#[inline]
fn do_transpose_16<SF: Fn(usize, usize) -> [u8; 32], DF: FnMut(usize, usize, [u8; 32])>(
    rows_div16: usize,
    cols_div16: usize,
    read_src: SF,
    mut write_dst: DF,
) {
    for i in 0..rows_div16 {
        for j in 0..cols_div16 {
            let m = read_src(i, j);
            let m_t = transpose_16x16(&m);
            write_dst(j, i, m_t);
        }
    }
}

/// Implement a transpose of a MxN bit matrix represented as `[BA{N}; {M}]` into a NxM bit matrix
/// represented as `[BA{M}; {N}]`.
///
/// The invocation looks like `impl_transpose_ba_to_ba!(BA<m>, BA<n>, <m>, <n>)`. e.g. for MxN = 16x64,
/// `impl_transpose_ba_to_ba!(BA16, BA64, 16, 64)`. Or to put it differently, write the MxN dimensions
/// twice, first with BA in front, and then without.
macro_rules! impl_transpose_ba_to_ba {
    ($dst_row:ty, $src_row:ty, $src_rows:expr, $src_cols:expr, $test_fn:ident) => {
        impl TransposeFrom<&[$src_row; $src_rows]> for [$dst_row; $src_cols] {
            type Error = Infallible;

            fn transpose_from(&mut self, src: &[$src_row; $src_rows]) -> Result<(), Infallible> {
                do_transpose_16(
                    $src_rows / 16,
                    $src_cols / 16,
                    |i, j| {
                        let mut d = [0u8; 32];
                        for k in 0..16 {
                            d[2 * k..2 * (k + 1)].copy_from_slice(
                                &src[16 * i + k].as_raw_slice()[2 * j..2 * (j + 1)],
                            );
                        }
                        d
                    },
                    |i, j, d| {
                        for k in 0..16 {
                            self[16 * i + k].as_raw_mut_slice()[2 * j..2 * (j + 1)]
                                .copy_from_slice(&d[2 * k..2 * (k + 1)]);
                        }
                    },
                );
                Ok(())
            }
        }

        #[cfg(all(test, unit_test))]
        #[test]
        fn $test_fn() {
            tests::test_transpose_ba_to_ba::<$dst_row, $src_row, $src_rows, $src_cols>();
        }

        impl TransposeFrom<&BitDecomposed<$src_row>> for Vec<$dst_row> {
            type Error = LengthError;

            fn transpose_from(&mut self, src: &BitDecomposed<$src_row>) -> Result<(), LengthError> {
                self.resize($src_cols, <$dst_row>::ZERO);
                let src = <&[$src_row; $src_rows]>::try_from(&**src).map_err(|_| LengthError {
                    expected: $src_rows,
                    actual: src.len(),
                })?;
                let dst = <&mut [$dst_row; $src_cols]>::try_from(&mut **self).unwrap();
                dst.transpose_from(src).unwrap_infallible();
                Ok(())
            }
        }

        impl TransposeFrom<&[$src_row; $src_rows]> for Vec<$dst_row> {
            type Error = Infallible;

            fn transpose_from(&mut self, src: &[$src_row; $src_rows]) -> Result<(), Infallible> {
                self.resize($src_cols, <$dst_row>::ZERO);
                let dst = <&mut [$dst_row; $src_cols]>::try_from(&mut **self).unwrap();
                dst.transpose_from(src)
            }
        }
    };
}

impl_transpose_ba_to_ba!(BA16, BA64, 16, 64, test_transpose_ba_16x64);
impl_transpose_ba_to_ba!(BA64, BA64, 64, 64, test_transpose_ba_64x64);
impl_transpose_ba_to_ba!(BA256, BA64, 256, 64, test_transpose_ba_256x64);
impl_transpose_ba_to_ba!(BA256, BA256, 256, 256, test_transpose_ba_256x256);

/// Implement a transpose of a MxN matrix of secret-shared bits represented as
/// `[AdditiveShare<Boolean, N>; <M>]` into a NxM bit matrix represented as `[AdditiveShare<BA<M>>; N]`.
///
/// For MxN = 256x64, the invocation looks like `impl_transpose_bool_to_ba!(BA256, 256, 64)`.
macro_rules! impl_transpose_shares_bool_to_ba {
    ($dst_row:ty, $src_rows:expr, $src_cols:expr, $test_fn:ident) => {
        impl TransposeFrom<&[AdditiveShare<Boolean, $src_cols>; $src_rows]>
            for [AdditiveShare<$dst_row>; $src_cols]
        {
            type Error = Infallible;

            fn transpose_from(
                &mut self,
                src: &[AdditiveShare<Boolean, $src_cols>; $src_rows],
            ) -> Result<(), Infallible> {
                // Transpose left share
                do_transpose_16(
                    $src_rows / 16,
                    $src_cols / 16,
                    |i, j| {
                        let mut d = [0u8; 32];
                        for k in 0..16 {
                            d[2 * k..2 * (k + 1)].copy_from_slice(
                                &src[16 * i + k].left_arr().as_raw_slice()[2 * j..2 * (j + 1)],
                            );
                        }
                        d
                    },
                    |i, j, d| {
                        for k in 0..16 {
                            self[16 * i + k].left_arr_mut().0[0].as_raw_mut_slice()
                                [2 * j..2 * (j + 1)]
                                .copy_from_slice(&d[2 * k..2 * (k + 1)]);
                        }
                    },
                );
                // Transpose right share
                do_transpose_16(
                    $src_rows / 16,
                    $src_cols / 16,
                    |i, j| {
                        let mut d = [0u8; 32];
                        for k in 0..16 {
                            d[2 * k..2 * (k + 1)].copy_from_slice(
                                &src[16 * i + k].right_arr().as_raw_slice()[2 * j..2 * (j + 1)],
                            );
                        }
                        d
                    },
                    |i, j, d| {
                        for k in 0..16 {
                            self[16 * i + k].right_arr_mut().0[0].as_raw_mut_slice()
                                [2 * j..2 * (j + 1)]
                                .copy_from_slice(&d[2 * k..2 * (k + 1)]);
                        }
                    },
                );
                Ok(())
            }
        }

        #[cfg(all(test, unit_test))]
        #[test]
        fn $test_fn() {
            tests::test_transpose_shares_bool_to_ba::<$dst_row, $src_rows, $src_cols>();
        }

        impl TransposeFrom<&BitDecomposed<AdditiveShare<Boolean, $src_cols>>>
            for Vec<AdditiveShare<$dst_row>>
        {
            type Error = LengthError;

            fn transpose_from(
                &mut self,
                src: &BitDecomposed<AdditiveShare<Boolean, $src_cols>>,
            ) -> Result<(), LengthError> {
                self.resize($src_cols, AdditiveShare::<$dst_row>::ZERO);
                let src = <&[AdditiveShare<Boolean, $src_cols>; $src_rows]>::try_from(&**src)
                    .map_err(|_| LengthError {
                        expected: $src_rows,
                        actual: src.len(),
                    })?;
                let dst =
                    <&mut [AdditiveShare<$dst_row>; $src_cols]>::try_from(&mut **self).unwrap();
                dst.transpose_from(src).unwrap_infallible();
                Ok(())
            }
        }
    };
}

impl_transpose_shares_bool_to_ba!(BA256, 256, 16, test_transpose_shares_bool_to_ba_256x16);
impl_transpose_shares_bool_to_ba!(BA256, 256, 64, test_transpose_shares_bool_to_ba_256x64);
impl_transpose_shares_bool_to_ba!(BA256, 256, 256, test_transpose_shares_bool_to_ba_256x256);

/// Implement a transpose of a MxN matrix of secret-shared bits accessed via
/// `Fn(usize) -> AdditiveShare<BA{N}>` into a NxM bit matrix represented as `[AdditiveShare<Boolean, M>; N]`.
///
/// For MxN = 256x64, the invocation looks like `impl_transpose_shares_ba_fn_to_bool!(BA64, 256, 64)`.
macro_rules! impl_transpose_shares_ba_fn_to_bool {
    ($src_row:ty, $src_rows:expr, $src_cols:expr, $test_fn:ident) => {
        // This function-based access to the source is useful when the source is not contiguous in
        // memory (i.e. accessing the match key for each input record). However, it does not
        // optimize as well as the other implementations (even without the dynamic dispatch).
        impl TransposeFrom<&dyn Fn(usize) -> AdditiveShare<$src_row>>
            for [AdditiveShare<Boolean, $src_rows>; $src_cols]
        {
            type Error = Infallible;

            fn transpose_from(
                &mut self,
                src: &dyn Fn(usize) -> AdditiveShare<$src_row>,
            ) -> Result<(), Infallible> {
                // Transpose left share
                do_transpose_16(
                    $src_rows / 16,
                    $src_cols / 16,
                    |i, j| {
                        let mut d = [0u8; 32];
                        for k in 0..16 {
                            d[2 * k..2 * (k + 1)].copy_from_slice(
                                &src(16 * i + k).left().as_raw_slice()[2 * j..2 * (j + 1)],
                            );
                        }
                        d
                    },
                    |i, j, d| {
                        for k in 0..16 {
                            self[16 * i + k].left_arr_mut().as_raw_mut_slice()[2 * j..2 * (j + 1)]
                                .copy_from_slice(&d[2 * k..2 * (k + 1)]);
                        }
                    },
                );
                // Transpose right share
                do_transpose_16(
                    $src_rows / 16,
                    $src_cols / 16,
                    |i, j| {
                        let mut d = [0u8; 32];
                        for k in 0..16 {
                            d[2 * k..2 * (k + 1)].copy_from_slice(
                                &src(16 * i + k).right().as_raw_slice()[2 * j..2 * (j + 1)],
                            );
                        }
                        d
                    },
                    |i, j, d| {
                        for k in 0..16 {
                            self[16 * i + k].right_arr_mut().as_raw_mut_slice()[2 * j..2 * (j + 1)]
                                .copy_from_slice(&d[2 * k..2 * (k + 1)]);
                        }
                    },
                );
                Ok(())
            }
        }

        impl TransposeFrom<&dyn Fn(usize) -> AdditiveShare<$src_row>>
            for BitDecomposed<AdditiveShare<Boolean, $src_rows>>
        {
            type Error = Infallible;

            fn transpose_from(
                &mut self,
                src: &dyn Fn(usize) -> AdditiveShare<$src_row>,
            ) -> Result<(), Infallible> {
                self.resize($src_cols, AdditiveShare::<Boolean, $src_rows>::ZERO);
                let dst =
                    <&mut [AdditiveShare<Boolean, $src_rows>; $src_cols]>::try_from(&mut **self)
                        .unwrap();
                dst.transpose_from(src)
            }
        }
    };
}

impl_transpose_shares_ba_fn_to_bool!(BA64, 16, 64, test_transpose_shares_ba_fn_to_bool_16x64);
impl_transpose_shares_ba_fn_to_bool!(BA64, 256, 64, test_transpose_shares_ba_fn_to_bool_256x64);

/// Implement a transpose of a MxN matrix of secret-shared bits represented as
/// `[AdditiveShare<Boolean, N>; <M>]` into a NxM bit matrix represented as `[AdditiveShare<Boolean<M>>; N]`.
///
/// For MxN = 256x64, the invocation looks like `impl_transpose_bool_to_bool!(BA64, 256, 64)`.
macro_rules! impl_transpose_shares_bool_to_bool {
    ($src_row:ty, $src_rows:expr, $src_cols:expr, $test_fn:ident) => {
        impl TransposeFrom<&[AdditiveShare<Boolean, $src_cols>; $src_rows]>
            for [AdditiveShare<Boolean, $src_rows>; $src_cols]
        {
            type Error = Infallible;

            fn transpose_from(
                &mut self,
                src: &[AdditiveShare<Boolean, $src_cols>; $src_rows],
            ) -> Result<(), Infallible> {
                // Transpose left share
                do_transpose_16(
                    $src_rows / 16,
                    $src_cols / 16,
                    |i, j| {
                        let mut d = [0u8; 32];
                        for k in 0..16 {
                            d[2 * k..2 * (k + 1)].copy_from_slice(
                                &src[16 * i + k].left_arr().as_raw_slice()[2 * j..2 * (j + 1)],
                            );
                        }
                        d
                    },
                    |i, j, d| {
                        for k in 0..16 {
                            self[16 * i + k].left_arr_mut().as_raw_mut_slice()[2 * j..2 * (j + 1)]
                                .copy_from_slice(&d[2 * k..2 * (k + 1)]);
                        }
                    },
                );
                // Transpose right share
                do_transpose_16(
                    $src_rows / 16,
                    $src_cols / 16,
                    |i, j| {
                        let mut d = [0u8; 32];
                        for k in 0..16 {
                            d[2 * k..2 * (k + 1)].copy_from_slice(
                                &src[16 * i + k].right_arr().as_raw_slice()[2 * j..2 * (j + 1)],
                            );
                        }
                        d
                    },
                    |i, j, d| {
                        for k in 0..16 {
                            self[16 * i + k].right_arr_mut().as_raw_mut_slice()[2 * j..2 * (j + 1)]
                                .copy_from_slice(&d[2 * k..2 * (k + 1)]);
                        }
                    },
                );
                Ok(())
            }
        }

        #[cfg(all(test, unit_test))]
        #[test]
        fn $test_fn() {
            tests::test_transpose_shares_bool_to_bool::<$src_rows, $src_cols>();
        }

        impl TransposeFrom<&[AdditiveShare<Boolean, $src_cols>]>
            for BitDecomposed<AdditiveShare<Boolean, $src_rows>>
        {
            type Error = LengthError;
            fn transpose_from(
                &mut self,
                src: &[AdditiveShare<Boolean, $src_cols>],
            ) -> Result<(), LengthError> {
                let src = <&[AdditiveShare<Boolean, $src_cols>; $src_rows]>::try_from(src)
                    .map_err(|_| LengthError {
                        expected: $src_rows,
                        actual: src.len(),
                    })?;
                self.transpose_from(src).unwrap_infallible();
                Ok(())
            }
        }

        impl TransposeFrom<&[AdditiveShare<Boolean, $src_cols>; $src_rows]>
            for BitDecomposed<AdditiveShare<Boolean, $src_rows>>
        {
            type Error = Infallible;
            fn transpose_from(
                &mut self,
                src: &[AdditiveShare<Boolean, $src_cols>; $src_rows],
            ) -> Result<(), Infallible> {
                self.resize($src_cols, AdditiveShare::<Boolean, $src_rows>::ZERO);
                let dst =
                    <&mut [AdditiveShare<Boolean, $src_rows>; $src_cols]>::try_from(&mut **self)
                        .unwrap();
                dst.transpose_from(src)
            }
        }
    };
}

impl_transpose_shares_bool_to_bool!(BA64, 16, 64, test_transpose_shares_bool_to_bool_16x64);
impl_transpose_shares_bool_to_bool!(BA64, 64, 64, test_transpose_shares_bool_to_bool_64x64);
impl_transpose_shares_bool_to_bool!(BA64, 256, 64, test_transpose_shares_bool_to_bool_256x64);

#[cfg(all(test, unit_test))]
mod tests {
    // Using `.enumerate()` would just obfuscate the nested for loops verifying transposes.
    #![allow(clippy::needless_range_loop)]

    use std::{
        cmp::min,
        fmt::Debug,
        iter::repeat_with,
        ops::{BitAnd, Not, Shl, Shr},
    };

    use rand::{
        distributions::{Distribution, Standard},
        thread_rng, Rng,
    };

    use super::*;
    use crate::{ff::ArrayAccess, secret_sharing::Vectorizable};

    fn random_array<T, const N: usize>() -> [T; N]
    where
        Standard: Distribution<T>,
    {
        let mut rng = thread_rng();
        array::from_fn(|_| rng.gen())
    }

    trait ByteConversion {
        type Bytes;
        fn into_bytes(self) -> Self::Bytes;
        fn from_bytes(bytes: Self::Bytes) -> Self;
    }

    impl ByteConversion for [u8; 8] {
        type Bytes = Self;

        fn into_bytes(self) -> Self::Bytes {
            self
        }

        fn from_bytes(bytes: Self::Bytes) -> Self {
            bytes
        }
    }

    macro_rules! impl_byte_conversion {
        ([$word:ty; $n_words:expr], [u8; $n_bytes:expr]) => {
            impl ByteConversion for [$word; $n_words] {
                type Bytes = [u8; $n_bytes];

                fn into_bytes(self) -> Self::Bytes {
                    self.into_iter()
                        .flat_map(<$word>::to_le_bytes)
                        .collect::<Vec<u8>>()
                        .try_into()
                        .unwrap()
                }

                fn from_bytes(bytes: Self::Bytes) -> Self {
                    const BYTES: usize = $n_bytes / $n_words;
                    bytes
                        .chunks_exact(BYTES)
                        .map(|slice| {
                            <$word>::from_le_bytes(<[u8; BYTES]>::try_from(slice).unwrap())
                        })
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap()
                }
            }
        };
    }

    impl_byte_conversion!([u16; 16], [u8; 32]);
    impl_byte_conversion!([u32; 32], [u8; 128]);
    impl_byte_conversion!([u64; 64], [u8; 512]);

    fn test_transpose_array<
        T,               // Matrix integer type (e.g. u16 for 16x16)
        const N: usize,  // Matrix dimension
        const NB: usize, // Matrix byte array size
    >(
        t_impl: fn(&[u8; NB]) -> [u8; NB],
    ) where
        T: Copy
            + Debug
            + Default
            + PartialEq<T>
            + Not<Output = T>
            + Shl<usize, Output = T>
            + Shr<usize, Output = T>
            + BitAnd<Output = T>,
        [T; N]: Copy + Debug + PartialEq<[T; N]> + ByteConversion<Bytes = [u8; NB]>,
    {
        let zero = T::default();
        let one = !zero >> (N - 1);

        // Identity
        let m: [u8; NB] = <[T; N]>::into_bytes(array::from_fn(|i| one << i));
        let m_t = t_impl(&m);
        assert_eq!(m_t, m);

        // Anti-diagonal
        let m: [u8; NB] = <[T; N]>::into_bytes(array::from_fn(|i| one << (N - 1 - i)));
        let m_t = t_impl(&m);
        assert_eq!(m_t, m);

        // Lower triangular
        let m: [u8; NB] = <[T; N]>::into_bytes(array::from_fn(|i| !zero >> (N - 1 - i)));
        let m_t = t_impl(&m);
        assert_eq!(<[T; N]>::from_bytes(m_t), array::from_fn(|i| !zero << i));

        // Random
        let m: [u8; NB] = random_array();
        let m_t = t_impl(&m);
        let m = <[T; N]>::from_bytes(m);
        let m_t = <[T; N]>::from_bytes(m_t);

        for i in 0..N {
            for j in 0..N {
                assert_eq!((m_t[i] >> j) & one, (m[j] >> i) & one);
            }
        }
    }

    #[test]
    fn transpose_8x8() {
        test_transpose_array::<u8, 8, 8>(|m| super::transpose_8x8(m));
    }

    #[test]
    fn transpose_16x16() {
        test_transpose_array::<u16, 16, 32>(super::transpose_16x16);
    }

    // The order of type parameters matches the implementation macro: BA<m>, BA<n>, <m>, <n>
    pub(super) fn test_transpose_ba_to_ba<
        DR,              // Destination row type
        SR,              // Source row type
        const SM: usize, // Source rows (== dest cols)
        const DM: usize, // Destination rows (== source cols)
    >()
    where
        SR: PartialEq<SR> + SharedValue + ArrayAccess<Output = Boolean>,
        DR: PartialEq<DR> + SharedValue + ArrayAccess<Output = Boolean>,
        [DR; DM]: for<'a> TransposeFrom<&'a [SR; SM], Error = Infallible>,
        Standard: Distribution<SR>,
    {
        let t_impl = |src| {
            let mut dst = [DR::ZERO; DM];
            dst.transpose_from(src).unwrap_infallible();
            dst
        };

        let step = min(SM, DM);
        let m = array::from_fn(|i| {
            let mut v = SR::ZERO;
            for j in ((i % DM)..DM).step_by(step) {
                v.set(j, Boolean::TRUE);
            }
            v
        });
        let m_t = t_impl(&m);
        assert_eq!(
            m_t,
            array::from_fn(|i| {
                let mut v = DR::ZERO;
                for j in ((i % SM)..SM).step_by(step) {
                    v.set(j, Boolean::TRUE);
                }
                v
            })
        );

        let mut rng = thread_rng();
        let m = repeat_with(|| rng.gen()).take(SM).collect::<Vec<_>>();
        let m_t = t_impl(<&[SR; SM]>::try_from(m.as_slice()).unwrap());

        for i in 0..DM {
            for j in 0..SM {
                assert_eq!(m_t[i].get(j), m[j].get(i));
            }
        }
    }

    // The order of type parameters matches the implementation macro: BA<m>, <m>, <n>
    pub(super) fn test_transpose_shares_bool_to_ba<
        DR,              // Destination row type
        const SM: usize, // Source rows (== dest cols)
        const DM: usize, // Destination rows (== source cols)
    >()
    where
        Boolean: Vectorizable<DM>,
        <Boolean as Vectorizable<DM>>::Array: ArrayAccess<Output = Boolean>,
        DR: SharedValue + ArrayAccess<Output = Boolean>,
        [AdditiveShare<DR>; DM]:
            for<'a> TransposeFrom<&'a [AdditiveShare<Boolean, DM>; SM], Error = Infallible>,
    {
        let t_impl = |src| {
            let mut dst = [AdditiveShare::<DR>::ZERO; DM];
            dst.transpose_from(src).unwrap_infallible();
            dst
        };

        let step = min(SM, DM);
        let m = array::from_fn(|i| {
            let mut left = vec![Boolean::FALSE; DM];
            let mut right = vec![Boolean::FALSE; DM];
            for j in ((i % DM)..DM).step_by(step) {
                let b = Boolean::from(j % 2 != 0);
                left[j] = b;
                right[j] = !b;
            }
            AdditiveShare::new_arr(
                <Boolean as Vectorizable<DM>>::Array::from_iter(left),
                <Boolean as Vectorizable<DM>>::Array::from_iter(right),
            )
        });
        let m_t = t_impl(&m);
        assert_eq!(
            m_t,
            array::from_fn(|i| {
                let mut v = AdditiveShare::<DR>::ZERO;
                for j in ((i % SM)..SM).step_by(step) {
                    let b = Boolean::from(j % 2 != 0);
                    v.set(j, AdditiveShare::new(b, !b));
                }
                v
            })
        );

        let mut left_rng = thread_rng();
        let mut right_rng = thread_rng();
        let m = repeat_with(|| AdditiveShare::from_fns(|_| left_rng.gen(), |_| right_rng.gen()))
            .take(SM)
            .collect::<Vec<_>>();
        let m_t = t_impl(<&[AdditiveShare<Boolean, DM>; SM]>::try_from(m.as_slice()).unwrap());

        for i in 0..DM {
            for j in 0..SM {
                assert_eq!(
                    m_t[i].get(j).unwrap().left(),
                    m[j].left_arr().get(i).unwrap()
                );
                assert_eq!(
                    m_t[i].get(j).unwrap().right(),
                    m[j].right_arr().get(i).unwrap()
                );
            }
        }
    }

    pub(super) fn test_transpose_shares_bool_to_bool<
        const SM: usize, // Source rows (== dest cols)
        const DM: usize, // Destination rows (== source cols)
    >()
    where
        Boolean: Vectorizable<DM>,
        <Boolean as Vectorizable<DM>>::Array: ArrayAccess<Output = Boolean>,
        Boolean: Vectorizable<SM>,
        <Boolean as Vectorizable<SM>>::Array: ArrayAccess<Output = Boolean>,
        [AdditiveShare<Boolean, SM>; DM]:
            for<'a> TransposeFrom<&'a [AdditiveShare<Boolean, DM>; SM], Error = Infallible>,
    {
        let t_impl = |src| {
            let mut dst = [AdditiveShare::<Boolean, SM>::ZERO; DM];
            dst.transpose_from(src).unwrap_infallible();
            dst
        };

        let step = min(SM, DM);
        let m = array::from_fn(|i| {
            let mut left = vec![Boolean::FALSE; DM];
            let mut right = vec![Boolean::FALSE; DM];
            for j in ((i % DM)..DM).step_by(step) {
                let b = Boolean::from(j % 2 != 0);
                left[j] = b;
                right[j] = !b;
            }
            AdditiveShare::new_arr(
                <Boolean as Vectorizable<DM>>::Array::from_iter(left),
                <Boolean as Vectorizable<DM>>::Array::from_iter(right),
            )
        });
        let m_t = t_impl(&m);
        assert_eq!(
            m_t,
            array::from_fn(|i| {
                let mut left = vec![Boolean::FALSE; SM];
                let mut right = vec![Boolean::FALSE; SM];
                for j in ((i % SM)..SM).step_by(step) {
                    let b = Boolean::from(j % 2 != 0);
                    left[j] = b;
                    right[j] = !b;
                }
                AdditiveShare::new_arr(
                    <Boolean as Vectorizable<SM>>::Array::from_iter(left),
                    <Boolean as Vectorizable<SM>>::Array::from_iter(right),
                )
            })
        );

        let mut left_rng = thread_rng();
        let mut right_rng = thread_rng();
        let m = repeat_with(|| AdditiveShare::from_fns(|_| left_rng.gen(), |_| right_rng.gen()))
            .take(SM)
            .collect::<Vec<_>>();
        let m_t = t_impl(<&[AdditiveShare<Boolean, DM>; SM]>::try_from(m.as_slice()).unwrap());

        for i in 0..DM {
            for j in 0..SM {
                assert_eq!(
                    m_t[i].left_arr().get(j).unwrap(),
                    m[j].left_arr().get(i).unwrap()
                );
                assert_eq!(
                    m_t[i].right_arr().get(j).unwrap(),
                    m[j].right_arr().get(i).unwrap()
                );
            }
        }
    }
}
