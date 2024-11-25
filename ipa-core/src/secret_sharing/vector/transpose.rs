//! # Bit matrix transpose operations
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

use std::{array, borrow::Borrow, convert::Infallible, ops::Deref};

use crate::{
    const_assert_eq,
    error::{LengthError, UnwrapInfallible},
    ff::{
        boolean::Boolean,
        boolean_array::{BA16, BA256, BA3, BA32, BA5, BA64, BA8},
        ec_prime_field::Fp25519,
    },
    protocol::ipa_prf::{CONV_CHUNK, MK_BITS},
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
        BitDecomposed, SharedValue, Vectorizable,
    },
};

// The following constants are hardcoded in various places throughout this file (including in type
// names like `BA256` where they cannot be substituted directly).
//
// The symbolic names are referenced in a comment adjacent to each use.
const_assert_eq!(
    Fp25519::BITS,
    256,
    "Appropriate transpose implementations required"
);
const_assert_eq!(
    MK_BITS,
    64,
    "Appropriate transpose implementations required"
);
const_assert_eq!(
    CONV_CHUNK,
    256,
    "Appropriate transpose implementations required"
);
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
//
// There are comments on `dzkp_field::bits_to_table_indices`, which implements a
// similar transformation, that may help to understand how this works.
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
//
// There are comments on `dzkp_field::bits_to_table_indices`, which implements a
// similar transformation, that may help to understand how this works.
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

// Matrix transpose helpers

// The read and write helpers are used with the `impl_transpose` macros to support a specific data
// type:
//  1. `impl_transpose` interprets the bit matrix in terms of 8x8 or 16x16 submatrices. It iterates
//     over the entire matrix, with `i` and `j` serving as row and column submatrix indices,
//     respectively.
//  2. `impl_transpose` invokes the selected `read_*` macro to transfer one submatrix
//     from the position (i, j) in the source source to temporary storage. The `read_*` macro is
//     invoked once for each row of the submatrix, with `k` as row index within the submatrix.
//  3. The submatrix is transposed.
//  4. `impl_transpose` invokes the selected `write_*` macro to write the transposed
//     submatrix at position (j, i) in the destination. As when reading, `k` indexes rows
//     within the submatrix.
//
// The `left` and `right` variants access data in the indicated share of a replicated sharing.  The
// `ba` variants access data in an array of `BA{n}` or an array of `AdditiveShare<BA{n}>`. The
// `bool` variants access data in an array of `AdditiveShare<Boolean, N>`. The `ba_fn_{left,right}`
// variants access data by calling a closure that returns `AdditiveShare<BA{n}>`. The `_8_pad`
// variants support reading data from a source that may not have the full height of 8, by padding
// with zeros.

macro_rules! read_ba_left_8_pad {
    ($m:ident, $src:ident, $i:ident, $j:ident, $k:ident, $pad_value:expr) => {
        $m[$k] = $src
            .get(8 * $i + $k)
            .unwrap_or($pad_value)
            .left()
            .as_raw_slice()[$j]
    };
}

macro_rules! read_ba_right_8_pad {
    ($m:ident, $src:ident, $i:ident, $j:ident, $k:ident, $pad_value:expr) => {
        $m[$k] = $src
            .get(8 * $i + $k)
            .unwrap_or($pad_value)
            .right()
            .as_raw_slice()[$j]
    };
}

macro_rules! write_ba_left_8 {
    ($dst:ident, $m:ident, $i:ident, $j:ident, $k:ident) => {
        $dst[8 * $i + $k].left_arr_mut().0[0].as_raw_mut_slice()[$j] = $m[$k]
    };
}

macro_rules! write_ba_right_8 {
    ($dst:ident, $m:ident, $i:ident, $j:ident, $k:ident) => {
        $dst[8 * $i + $k].right_arr_mut().0[0].as_raw_mut_slice()[$j] = $m[$k]
    };
}

macro_rules! read_bool_left_8 {
    ($m:ident, $src:ident, $i:ident, $j:ident, $k:ident) => {
        $m[$k] = $src[8 * $i + $k].left_arr().as_raw_slice()[$j]
    };
}

macro_rules! read_bool_right_8 {
    ($m:ident, $src:ident, $i:ident, $j:ident, $k:ident) => {
        $m[$k] = $src[8 * $i + $k].right_arr().as_raw_slice()[$j]
    };
}

macro_rules! write_bool_left_8 {
    ($dst:ident, $m:ident, $i:ident, $j:ident, $k:ident) => {
        $dst[8 * $i + $k].left_arr_mut().as_raw_mut_slice()[$j] = $m[$k]
    };
}

macro_rules! write_bool_right_8 {
    ($dst:ident, $m:ident, $i:ident, $j:ident, $k:ident) => {
        $dst[8 * $i + $k].right_arr_mut().as_raw_mut_slice()[$j] = $m[$k]
    };
}

macro_rules! read_ba_16 {
    ($m:ident, $src:ident, $i:ident, $j:ident, $k:ident) => {
        $m[2 * $k..2 * ($k + 1)]
            .copy_from_slice(&$src[16 * $i + $k].as_raw_slice()[2 * $j..2 * ($j + 1)])
    };
}

macro_rules! read_ba_left_16 {
    ($m:ident, $src:ident, $i:ident, $j:ident, $k:ident) => {
        $m[2 * $k..2 * ($k + 1)]
            .copy_from_slice(&$src[16 * $i + $k].left().as_raw_slice()[2 * $j..2 * ($j + 1)])
    };
}

macro_rules! read_ba_right_16 {
    ($m:ident, $src:ident, $i:ident, $j:ident, $k:ident) => {
        $m[2 * $k..2 * ($k + 1)]
            .copy_from_slice(&$src[16 * $i + $k].right().as_raw_slice()[2 * $j..2 * ($j + 1)])
    };
}

macro_rules! read_ba_fn_left_16 {
    ($m:ident, $src:ident, $i:ident, $j:ident, $k:ident) => {
        $m[2 * $k..2 * ($k + 1)]
            .copy_from_slice(&$src(16 * $i + $k).left().as_raw_slice()[2 * $j..2 * ($j + 1)])
    };
}

macro_rules! read_ba_fn_right_16 {
    ($m:ident, $src:ident, $i:ident, $j:ident, $k:ident) => {
        $m[2 * $k..2 * ($k + 1)]
            .copy_from_slice(&$src(16 * $i + $k).right().as_raw_slice()[2 * $j..2 * ($j + 1)])
    };
}

macro_rules! write_ba_16 {
    ($dst:ident, $m:ident, $i:ident, $j:ident, $k:ident) => {
        $dst[16 * $i + $k].as_raw_mut_slice()[2 * $j..2 * ($j + 1)]
            .copy_from_slice(&$m[2 * $k..2 * ($k + 1)]);
    };
}

macro_rules! write_ba_left_16 {
    ($dst:ident, $m:ident, $i:ident, $j:ident, $k:ident) => {
        $dst[16 * $i + $k].left_arr_mut().0[0].as_raw_mut_slice()[2 * $j..2 * ($j + 1)]
            .copy_from_slice(&$m[2 * $k..2 * ($k + 1)]);
    };
}

macro_rules! write_ba_right_16 {
    ($dst:ident, $m:ident, $i:ident, $j:ident, $k:ident) => {
        $dst[16 * $i + $k].right_arr_mut().0[0].as_raw_mut_slice()[2 * $j..2 * ($j + 1)]
            .copy_from_slice(&$m[2 * $k..2 * ($k + 1)]);
    };
}

macro_rules! read_bool_left_16 {
    ($m:ident, $src:ident, $i:ident, $j:ident, $k:ident) => {
        $m[2 * $k..2 * ($k + 1)]
            .copy_from_slice(&$src[16 * $i + $k].left_arr().as_raw_slice()[2 * $j..2 * ($j + 1)])
    };
}

macro_rules! read_bool_right_16 {
    ($m:ident, $src:ident, $i:ident, $j:ident, $k:ident) => {
        $m[2 * $k..2 * ($k + 1)]
            .copy_from_slice(&$src[16 * $i + $k].right_arr().as_raw_slice()[2 * $j..2 * ($j + 1)])
    };
}

macro_rules! write_bool_left_16 {
    ($dst:ident, $m:ident, $i:ident, $j:ident, $k:ident) => {
        $dst[16 * $i + $k].left_arr_mut().as_raw_mut_slice()[2 * $j..2 * ($j + 1)]
            .copy_from_slice(&$m[2 * $k..2 * ($k + 1)])
    };
}

macro_rules! write_bool_right_16 {
    ($dst:ident, $m:ident, $i:ident, $j:ident, $k:ident) => {
        $dst[16 * $i + $k].right_arr_mut().as_raw_mut_slice()[2 * $j..2 * ($j + 1)]
            .copy_from_slice(&$m[2 * $k..2 * ($k + 1)])
    };
}

/// Implement a larger transpose using the 8x8 kernel.
///
/// Matrix height and width must be multiples of 8.
macro_rules! impl_transpose_8 {
    ($dst:ident, $src:ident, $src_rows:expr, $src_cols:expr, $read:ident, $write:ident $(,)?) => {
        debug_assert!(
            $src_rows % 8 == 0 && $src_cols % 8 == 0,
            "This implementation requires that both dimensions are multiples of 8",
        );

        for i in 0..$src_rows / 8 {
            for j in 0..$src_cols / 8 {
                let mut m = [0u8; 8];
                for k in 0..8 {
                    $read!(m, $src, i, j, k);
                }
                let m_t = transpose_8x8(&m);
                for k in 0..8 {
                    $write!($dst, m_t, j, i, k);
                }
            }
        }
    };
}

/// Implement a larger transpose using the 8x8 kernel.
///
/// Matrix height and width do not need to be multiples of 8, however, the row stride in memory must
/// still be a multiple of 8 (i.e. whole bytes).
macro_rules! impl_transpose_8_pad {
    ($dst:ident, $src:ident, $src_rows:expr, $src_cols:expr, $read:ident, $pad_value:expr, $write:ident $(,)?) => {
        for i in 0..($src_rows + 7) / 8 {
            for j in 0..($src_cols + 7) / 8 {
                let mut m = [0u8; 8];
                for k in 0..8 {
                    $read!(m, $src, i, j, k, $pad_value);
                }
                let m_t = transpose_8x8(&m);
                for k in 0..8 {
                    $write!($dst, m_t, j, i, k);
                }
            }
        }
    };
}

/// Implement a larger transpose using the 16x16 kernel.
///
/// Matrix height and width must be multiples of 16.
macro_rules! impl_transpose_16 {
    ($dst:ident, $src:ident, $src_rows:expr, $src_cols:expr, $read:ident, $write:ident $(,)?) => {
        debug_assert!(
            $src_rows % 16 == 0 && $src_cols % 16 == 0,
            "This implementation requires that both dimensions are multiples of 16",
        );

        for i in 0..$src_rows / 16 {
            for j in 0..$src_cols / 16 {
                let mut m = [0u8; 32];
                for k in 0..16 {
                    $read!(m, $src, i, j, k);
                }
                let m_t = transpose_16x16(&m);
                for k in 0..16 {
                    $write!($dst, m_t, j, i, k);
                }
            }
        }
    };
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

// Helper for `impl_transpose_shim` that performs a `TryFrom` conversion for the source,
// if applicable. For example, a `Vec` dereferences to a slice, which then must be
// converted to an array using `TryFrom`.
macro_rules! transpose_shim_convert_src {
    ($converted:ty, $expected_len:expr, $src:ident, LengthError) => {
        <$converted>::try_from($src.deref()).map_err(|_| LengthError {
            expected: $expected_len,
            actual: $src.len(),
        })?
    };
    ($converted:ty, $expected_len:expr, $src:ident, Infallible) => {
        $src
    };
}

// Implement a transpose shim that adapts a transpose implementation for arrays into a transpose
// implementation for some other type like `BitDecomposed` or `Vec`.
macro_rules! impl_transpose_shim {
    ($src_ty:ty, $src_row:ty, $dst_ty:ty, $dst_row:ty, $src_rows:expr, $src_cols:expr, $error:tt $(,)?) => {
        impl TransposeFrom<$src_ty> for $dst_ty {
            type Error = $error;
            fn transpose_from(&mut self, src: $src_ty) -> Result<(), Self::Error> {
                self.resize($src_cols, <$dst_row>::ZERO);
                let src =
                    transpose_shim_convert_src!(&[$src_row; $src_rows], $src_rows, src, $error);
                // This unwrap cannot fail, because we resized `self` to the proper size.
                let dst = <&mut [$dst_row; $src_cols]>::try_from(&mut **self).unwrap();
                dst.transpose_from(src).unwrap_infallible();
                Ok(())
            }
        }
    };
}

// Variant of impl_transpose_shim that adjusts non-multiple-of-8 sizes to the next multiple of 8.
macro_rules! impl_transpose_shim_8_pad {
    ($src_ty:ty, $src_row:ty, $dst_ty:ty, $dst_row:ty, $src_rows:expr, $src_cols:expr, $error:tt $(,)?) => {
        impl TransposeFrom<$src_ty> for $dst_ty {
            type Error = $error;
            fn transpose_from(&mut self, src: $src_ty) -> Result<(), Self::Error> {
                self.resize(($src_cols + 7) / 8 * 8, <$dst_row>::ZERO);
                let src =
                    transpose_shim_convert_src!(&[$src_row; $src_rows], $src_rows, src, $error);
                // This unwrap cannot fail, because we resized `self` to the proper size.
                let dst =
                    <&mut [$dst_row; ($src_cols + 7) / 8 * 8]>::try_from(&mut **self).unwrap();
                dst.transpose_from(src).unwrap_infallible();
                self.truncate($src_cols);
                Ok(())
            }
        }
    };
}

// Matrix transposes

/// Implement a transpose of a MxN bit matrix represented as `[BA{N}; {M}]` into a NxM bit matrix
/// represented as `[BA{M}; {N}]`.
///
/// The invocation looks like `impl_transpose_ba_to_ba!(BA<m>, BA<n>, <m>, <n>)`. e.g. for MxN = 16x64,
/// `impl_transpose_ba_to_ba!(BA16, BA64, 16, 64)`. Or to put it differently, write the MxN dimensions
/// twice, first with BA in front, and then without.
macro_rules! impl_transpose_ba_to_ba {
    ($dst_row:ty, $src_row:ty, $src_rows:expr, $src_cols:expr, $test_fn:ident $(,)?) => {
        impl TransposeFrom<&[$src_row; $src_rows]> for [$dst_row; $src_cols] {
            type Error = Infallible;

            fn transpose_from(&mut self, src: &[$src_row; $src_rows]) -> Result<(), Infallible> {
                impl_transpose_16!(self, src, $src_rows, $src_cols, read_ba_16, write_ba_16);
                Ok(())
            }
        }

        #[cfg(all(test, unit_test))]
        #[test]
        fn $test_fn() {
            tests::test_transpose_ba_to_ba::<$dst_row, $src_row, $src_rows, $src_cols>();
        }

        impl_transpose_shim!(
            &[$src_row; $src_rows],
            $src_row,
            Vec<$dst_row>,
            $dst_row,
            $src_rows,
            $src_cols,
            Infallible,
        );
    };
}

// Input: MxN as `[BA{N}; {M}]` or similar
// Output: NxM as `[BA{M}; {N}]` or similar
// Arguments: BA{M}, BA{N}, M, N
// Dimensions: Multiples of 16.

// Usage: Transpose benchmark.
impl_transpose_ba_to_ba!(BA64, BA64, 64, 64, test_transpose_ba_64x64);

// Usage: Share conversion output (y). M = Fp25519::BITS, N = CONV_CHUNK.
impl_transpose_ba_to_ba!(BA256, BA256, 256, 256, test_transpose_ba_256x256);

/// Implement a transpose of a MxN matrix of secret-shared bits represented as
/// `[AdditiveShare<Boolean, N>; <M>]` into a NxM bit matrix represented as `[AdditiveShare<BA<M>>; N]`.
///
/// For MxN = 256x64, the invocation looks like `impl_transpose_shares_bool_to_ba!(BA256, 256, 64)`.
///
/// The dimensions must be multiples of 16.
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
                impl_transpose_16!(self, src, $src_rows, $src_cols, read_bool_left_16, write_ba_left_16);
                impl_transpose_16!(self, src, $src_rows, $src_cols, read_bool_right_16, write_ba_right_16);
                Ok(())
            }
        }

        #[cfg(all(test, unit_test))]
        #[test]
        fn $test_fn() {
            tests::test_transpose_shares_bool_to_ba::<$dst_row, $src_rows, $src_cols>();
        }

        impl_transpose_shim!(
            &BitDecomposed<AdditiveShare<Boolean, $src_cols>>, AdditiveShare<Boolean, $src_cols>,
            Vec<AdditiveShare<$dst_row>>, AdditiveShare<$dst_row>,
            $src_rows, $src_cols,
            LengthError,
        );
    };
}

/// Variant of `impl_transpose_shares_bool_to_ba` supporting dimensions that are multiples of 8.
macro_rules! impl_transpose_shares_bool_to_ba_small {
    ($dst_row:ty, $src_rows:expr, $src_cols:expr, $test_fn:ident) => {
        impl TransposeFrom<&[AdditiveShare<Boolean, $src_cols>; $src_rows]>
            for [AdditiveShare<$dst_row>; $src_cols]
        {
            type Error = Infallible;

            fn transpose_from(
                &mut self,
                src: &[AdditiveShare<Boolean, $src_cols>; $src_rows],
            ) -> Result<(), Infallible> {
                impl_transpose_8!(self, src, $src_rows, $src_cols, read_bool_left_8, write_ba_left_8);
                impl_transpose_8!(self, src, $src_rows, $src_cols, read_bool_right_8, write_ba_right_8);
                Ok(())
            }
        }

        #[cfg(all(test, unit_test))]
        #[test]
        fn $test_fn() {
            tests::test_transpose_shares_bool_to_ba::<$dst_row, $src_rows, $src_cols>();
        }

        impl_transpose_shim!(
            &BitDecomposed<AdditiveShare<Boolean, $src_cols>>, AdditiveShare<Boolean, $src_cols>,
            Vec<AdditiveShare<$dst_row>>, AdditiveShare<$dst_row>,
            $src_rows, $src_cols,
            LengthError,
        );
    };
}

// Input: MxN as `[AdditiveShare<Boolean, N>; {M}]` or similar
// Output: NxM as `[AdditiveShare<BA{M}>; N]` or similar
// Arguments: BA{M}, M, N
// Dimensions: Multiples of 16, or 8 for small variant.

// Usage: Share conversion output (r/s). M = Fp25519::BITS, N = CONV_CHUNK.
impl_transpose_shares_bool_to_ba!(BA256, 256, 256, test_transpose_shares_bool_to_ba_256x256);

// Usage: Aggregation output. M = HV bits, N = number of breakdowns.
// (for feature_label_dot_product, N = number of features)
impl_transpose_shares_bool_to_ba_small!(BA8, 8, 256, test_transpose_shares_bool_to_ba_8x256);

impl_transpose_shares_bool_to_ba!(BA16, 16, 256, test_transpose_shares_bool_to_ba_16x256);
impl_transpose_shares_bool_to_ba!(BA16, 16, 32, test_transpose_shares_bool_to_ba_16x32);
impl_transpose_shares_bool_to_ba!(BA32, 32, 256, test_transpose_shares_bool_to_ba_32x256);
impl_transpose_shares_bool_to_ba_small!(BA8, 8, 32, test_transpose_shares_bool_to_ba_8x32);
// added to support HV = BA32 to hold results when adding Binomial noise
impl_transpose_shares_bool_to_ba_small!(BA32, 32, 32, test_transpose_shares_bool_to_ba_32x32);

// Usage: Aggregation output tests
impl_transpose_shares_bool_to_ba_small!(BA8, 8, 8, test_transpose_shares_bool_to_ba_8x8);

// Usage: Binomial Noise Gen
impl_transpose_shares_bool_to_ba!(BA16, 16, 16, test_transpose_shares_bool_to_ba_16x16);

// Usage: ?
impl_transpose_shares_bool_to_ba_small!(BA8, 8, 16, test_transpose_shares_bool_to_ba_8x16);

/// Implement a transpose of a MxN matrix of secret-shared bits represented as
/// `[AdditiveShare<BA<N>>; M]` into a NxM bit matrix represented as `[AdditiveShare<Boolean, M>; N]`.
///
/// For MxN = 16x64, the invocation looks like `impl_transpose_shares_ba_to_bool!(BA64, 16, 64)`.
macro_rules! impl_transpose_shares_ba_to_bool {
    ($src_row:ty, $src_rows:expr, $src_cols:expr, $test_fn:ident) => {
        impl TransposeFrom<&[AdditiveShare<$src_row>; $src_rows]>
            for [AdditiveShare<Boolean, $src_rows>; $src_cols]
        {
            type Error = Infallible;
            fn transpose_from(
                &mut self,
                src: &[AdditiveShare<$src_row>; $src_rows],
            ) -> Result<(), Infallible> {
                impl_transpose_16!(self, src, $src_rows, $src_cols, read_ba_left_16, write_bool_left_16);
                impl_transpose_16!(self, src, $src_rows, $src_cols, read_ba_right_16, write_bool_right_16);
                Ok(())
            }
        }

        #[cfg(all(test, unit_test))]
        #[test]
        fn $test_fn() {
            tests::test_transpose_shares_ba_to_bool::<$src_row, $src_rows, $src_cols>();
        }

        impl_transpose_shim!(
            &[AdditiveShare<$src_row>; $src_rows], AdditiveShare<$src_row>,
            BitDecomposed<AdditiveShare<Boolean, $src_rows>>, AdditiveShare<Boolean, $src_rows>,
            $src_rows, $src_cols,
            Infallible,
        );
    };
}

// Input: MxN as `[AdditiveShare<BA{N}>; M]` or similar
// Output: NxM as `[AdditiveShare<Boolean, M>; N]` or similar
// Arguments: BA{N}, M, N
//  --> Note: first macro argument is `BA{N}`, not `BA{M}`.
// Dimensions: Multiples of 16.

// Usage: Share conversion input (convert_to_fp25519 test). M = CONV_CHUNK, N = MK_BITS.
impl_transpose_shares_ba_to_bool!(BA64, 256, 64, test_transpose_shares_ba_to_bool_256x64);

// Usage: Quicksort. M = SORT_CHUNK, N = sort key bits.
impl_transpose_shares_ba_to_bool!(BA32, 256, 32, test_transpose_shares_ba_to_bool_256x32);

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
                impl_transpose_16!(self, src, $src_rows, $src_cols, read_ba_fn_left_16, write_bool_left_16);
                impl_transpose_16!(self, src, $src_rows, $src_cols, read_ba_fn_right_16, write_bool_right_16);
                Ok(())
            }
        }

        #[cfg(all(test, unit_test))]
        #[test]
        fn $test_fn() {
            tests::test_transpose_shares_ba_fn_to_bool::<$src_row, $src_rows, $src_cols>();
        }

        impl_transpose_shim!(
            &dyn Fn(usize) -> AdditiveShare<$src_row>, AdditiveShare<$src_row>,
            BitDecomposed<AdditiveShare<Boolean, $src_rows>>, AdditiveShare<Boolean, $src_rows>,
            $src_rows, $src_cols,
            Infallible,
        );
    };
}

// Input: MxN as `&dyn Fn(usize) -> AdditiveShare<BA{N}>`
// Output: NxM as `[AdditiveShare<Boolean, M>; N]` or similar
// Arguments: BA{N}, M, N
//  --> Note: first macro argument is `BA{N}`, not `BA{M}`.
// Dimensions: Multiples of 16.

// Usage: Share conversion input (compute_prf_for_inputs). M = CONV_CHUNK, N = MK_BITS.
impl_transpose_shares_ba_fn_to_bool!(BA64, 256, 64, test_transpose_shares_ba_fn_to_bool_256x64);

/// Implement a transpose of a MxN matrix of secret-shared bits represented as
/// `[AdditiveShare<BA<N>>; M]` into a NxM bit matrix represented as `[AdditiveShare<Boolean, M>; N]`.
///
/// For MxN = 16x64, the invocation looks like `impl_transpose_shares_ba_to_bool_small!(BA64, 16, 64)`.
///
/// This version uses the 8x8 transpose kernel and supports dimensions that are not a multiple of 8.
macro_rules! impl_transpose_shares_ba_to_bool_small {
    ($src_row:ty, $src_rows:expr, $src_cols:expr, $test_fn:ident) => {
        impl TransposeFrom<&[AdditiveShare<$src_row>; $src_rows]>
            for [AdditiveShare<Boolean, $src_rows>; ($src_cols + 7) / 8 * 8]
        {
            type Error = Infallible;
            fn transpose_from(
                &mut self,
                src: &[AdditiveShare<$src_row>; $src_rows],
            ) -> Result<(), Infallible> {
                impl_transpose_8_pad!(
                    self, src,
                    $src_rows, $src_cols,
                    read_ba_left_8_pad, &AdditiveShare::<$src_row>::ZERO,
                    write_bool_left_8,
                );
                impl_transpose_8_pad!(
                    self, src,
                    $src_rows, $src_cols,
                    read_ba_right_8_pad, &AdditiveShare::<$src_row>::ZERO,
                    write_bool_right_8,
                );
                Ok(())
            }
        }

        #[cfg(all(test, unit_test))]
        #[test]
        fn $test_fn() {
            tests::test_transpose_shares_ba_to_bool_small::<$src_row, $src_rows, $src_cols>();
        }

        impl_transpose_shim_8_pad!(
            &[AdditiveShare<$src_row>; $src_rows], AdditiveShare<$src_row>,
            BitDecomposed<AdditiveShare<Boolean, $src_rows>>, AdditiveShare<Boolean, $src_rows>,
            $src_rows, $src_cols,
            Infallible,
        );

        impl_transpose_shim_8_pad!(
            &Vec<AdditiveShare<$src_row>>, AdditiveShare<$src_row>,
            BitDecomposed<AdditiveShare<Boolean, $src_rows>>, AdditiveShare<Boolean, $src_rows>,
            $src_rows, $src_cols,
            LengthError,
        );
    };
}

// Input: MxN as `[AdditiveShare<BA{N}>; M]` or similar
// Output: NxM as `[AdditiveShare<Boolean, M>; N]` or similar
// Arguments: BA{N}, M, N
//  --> Note: first macro argument is `BA{N}`, not `BA{M}`.
// Dimensions: Arbitrary (rows are padded to whole bytes).

// Usage: Aggregation input. M = AGG_CHUNK, N = BK or TV bits.
impl_transpose_shares_ba_to_bool_small!(BA16, 256, 16, test_transpose_shares_ba_to_bool_256x16);
impl_transpose_shares_ba_to_bool_small!(BA8, 256, 8, test_transpose_shares_ba_to_bool_256x8);
impl_transpose_shares_ba_to_bool_small!(BA5, 256, 5, test_transpose_shares_ba_to_bool_256x5);
impl_transpose_shares_ba_to_bool_small!(BA3, 256, 3, test_transpose_shares_ba_to_bool_256x3);

// Usage: feature_label_dot_product aggregation input. M = number of features, N = BK or TV bits.
impl_transpose_shares_ba_to_bool_small!(BA8, 32, 8, test_transpose_shares_ba_to_bool_32x8);

// Usage tests for aggregation based on reveal
impl_transpose_shares_ba_to_bool_small!(BA3, 32, 3, test_transpose_shares_ba_to_bool_32x3);

// Usage: Laplace noise mechanism. M = number of breakdowns (2^|bk|), N = OV bits.
impl_transpose_shares_ba_to_bool!(BA32, 32, 32, test_transpose_shares_ba_to_bool_32x32);
impl_transpose_shares_ba_to_bool!(BA16, 32, 16, test_transpose_shares_ba_to_bool_32x16);
impl_transpose_shares_ba_to_bool_small!(BA8, 16, 8, test_transpose_shares_ba_to_bool_16x8);

// Special transpose used for "aggregation intermediate". See [`aggregate_contributions`] for
// additional details.
//
// The input to this transpose is `&[BitDecomposed<AdditiveShare<Boolean, {agg chunk}>>]`, indexed
// by buckets, bits of trigger value, and contribution rows.
//
// The output is `&[BitDecomposed<AdditiveShare<Boolean, {buckets}>>]`, indexed by
// contribution rows, bits of trigger value, and buckets.
//
// The transpose operates on contribution rows and buckets. It proceeds identically for
// each trigger value bit, just like it does for the left and right shares. However, because
// the trigger value bits exist between the row and bucket indexing, a special transpose
// implementation is required for this case.
macro_rules! impl_aggregation_transpose {
    ($dst_row:ty, $src_row:ty, $src_rows:expr, $src_cols:expr, $test_fn:ident $(,)?) => {
        impl TransposeFrom<&[BitDecomposed<AdditiveShare<Boolean, $src_cols>>]>
            for Vec<BitDecomposed<AdditiveShare<Boolean, $src_rows>>>
        where
            Boolean: Vectorizable<$src_rows, Array = $dst_row>
                + Vectorizable<$src_cols, Array = $src_row>,
        {
            type Error = Infallible;

            fn transpose_from(
                &mut self,
                src: &[BitDecomposed<AdditiveShare<Boolean, $src_cols>>],
            ) -> Result<(), Infallible> {
                self.resize(
                    $src_cols,
                    vec![AdditiveShare::<Boolean, $src_rows>::ZERO; src[0].len()]
                        .try_into()
                        .unwrap(),
                );
                for b in 0..src[0].len() {
                    // Transpose left share
                    do_transpose_16(
                        $src_rows / 16,
                        $src_cols / 16,
                        |i, j| {
                            let mut d = [0u8; 32];
                            for k in 0..16 {
                                d[2 * k..2 * (k + 1)].copy_from_slice(
                                    &src[16 * i + k][b].left_arr().as_raw_slice()
                                        [2 * j..2 * (j + 1)],
                                );
                            }
                            d
                        },
                        |i, j, d| {
                            for k in 0..16 {
                                self[16 * i + k][b].left_arr_mut().as_raw_mut_slice()
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
                                    &src[16 * i + k][b].right_arr().as_raw_slice()
                                        [2 * j..2 * (j + 1)],
                                );
                            }
                            d
                        },
                        |i, j, d| {
                            for k in 0..16 {
                                self[16 * i + k][b].right_arr_mut().as_raw_mut_slice()
                                    [2 * j..2 * (j + 1)]
                                    .copy_from_slice(&d[2 * k..2 * (k + 1)]);
                            }
                        },
                    );
                }
                Ok(())
            }
        }

        #[cfg(all(test, unit_test))]
        #[test]
        fn $test_fn() {
            tests::test_aggregation_transpose::<$src_rows, $src_cols>();
        }
    };
}

// Usage: aggregation intermediate. M = number of breakdowns (2^|bk|), N = AGG_CHUNK
// Arguments: BA{M}, BA{N}, M, N
impl_aggregation_transpose!(BA256, BA256, 256, 256, test_aggregation_transpose_256x256);
impl_aggregation_transpose!(BA32, BA256, 32, 256, test_aggregation_transpose_32x256);

#[cfg(all(test, unit_test))]
mod tests {
    use std::{
        cmp::min,
        fmt::Debug,
        iter::{repeat_with, zip},
        ops::{BitAnd, Not, Shl, Shr},
    };

    use rand::{
        distributions::{Distribution, Standard},
        thread_rng, Rng,
    };

    use super::*;
    use crate::{
        ff::{boolean_array::BooleanArray, ArrayAccess},
        secret_sharing::Vectorizable,
    };

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

    fn verify_transpose<T, F1, F2>(src_rows: usize, src_cols: usize, transposed: F1, original: F2)
    where
        T: PartialEq + Debug,
        F1: Fn(usize, usize) -> T,
        F2: Fn(usize, usize) -> T,
    {
        for i in 0..src_cols {
            for j in 0..src_rows {
                assert_eq!(transposed(i, j), original(j, i));
            }
        }
    }

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

        verify_transpose(N, N, |i, j| (m_t[i] >> j) & one, |i, j| (m[i] >> j) & one);
    }

    #[test]
    fn transpose_8x8() {
        test_transpose_array::<u8, 8, 8>(|m| super::transpose_8x8(m));
    }

    #[test]
    fn transpose_16x16() {
        test_transpose_array::<u16, 16, 32>(super::transpose_16x16);
    }

    fn ba_shares_test_matrix<BA: BooleanArray, const M: usize, const N: usize>(
        step: usize,
    ) -> [AdditiveShare<BA>; M] {
        array::from_fn(|i| {
            let mut left = vec![Boolean::FALSE; N];
            let mut right = vec![Boolean::FALSE; N];
            for j in ((i % N)..N).step_by(step) {
                let b = Boolean::from((j / N) % 2 != 0);
                left[j] = b;
                right[j] = !b;
            }
            AdditiveShare::new_arr(
                BA::from_iter(left).into_array(),
                BA::from_iter(right).into_array(),
            )
        })
    }

    fn bool_shares_test_matrix<const M: usize, const N: usize>(
        step: usize,
    ) -> [AdditiveShare<Boolean, N>; M]
    where
        Boolean: Vectorizable<N>,
    {
        array::from_fn(|i| {
            let mut left = vec![Boolean::FALSE; N];
            let mut right = vec![Boolean::FALSE; N];
            for j in ((i % N)..N).step_by(step) {
                let b = Boolean::from((j / N) % 2 != 0);
                left[j] = b;
                right[j] = !b;
            }
            AdditiveShare::new_arr(
                <Boolean as Vectorizable<N>>::Array::from_iter(left),
                <Boolean as Vectorizable<N>>::Array::from_iter(right),
            )
        })
    }

    // The order of type parameters matches the implementation macro: BA<m>, BA<n>, <m>, <n>
    pub(super) fn test_transpose_ba_to_ba<
        DR,              // Destination row type
        SR,              // Source row type
        const SM: usize, // Source rows (== dest cols)
        const DM: usize, // Destination rows (== source cols)
    >()
    where
        SR: PartialEq<SR> + BooleanArray,
        DR: PartialEq<DR> + BooleanArray,
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

        verify_transpose(SM, DM, |i, j| m_t[i].get(j), |i, j| m[i].get(j));
    }

    // The order of type parameters matches the implementation macro: BA<n>, <m>, <n>
    pub(super) fn test_transpose_shares_ba_to_bool<
        SR,              // Source row type
        const SM: usize, // Source rows (== dest cols)
        const DM: usize, // Destination rows (== source cols)
    >()
    where
        Boolean: Vectorizable<SM>,
        <Boolean as Vectorizable<SM>>::Array: BooleanArray,
        SR: BooleanArray,
        [AdditiveShare<Boolean, SM>; DM]:
            for<'a> TransposeFrom<&'a [AdditiveShare<SR>; SM], Error = Infallible>,
        Standard: Distribution<SR>,
    {
        let t_impl = |src| {
            let mut dst = [AdditiveShare::<Boolean, SM>::ZERO; DM];
            dst.transpose_from(src).unwrap_infallible();
            dst
        };

        let step = min(SM, DM);
        let m = ba_shares_test_matrix::<SR, SM, DM>(step);
        let m_t = t_impl(&m);
        assert_eq!(m_t, bool_shares_test_matrix::<DM, SM>(step));

        let mut left_rng = thread_rng();
        let mut right_rng = thread_rng();
        let m = repeat_with(|| AdditiveShare::from_fns(|_| left_rng.gen(), |_| right_rng.gen()))
            .take(SM)
            .collect::<Vec<_>>();
        let m_t = t_impl(<&[AdditiveShare<SR>; SM]>::try_from(m.as_slice()).unwrap());

        #[rustfmt::skip]
        verify_transpose(SM, DM,
            |i, j| (m_t[i].left_arr().get(j).unwrap(), m_t[i].right_arr().get(j).unwrap()),
            |i, j| (m[i].get(j).unwrap().left(), m[i].get(j).unwrap().right()),
        );
    }

    // The order of type parameters matches the implementation macro: BA<n>, <m>, <n>
    pub(super) fn test_transpose_shares_ba_to_bool_small<
        SR,              // Source row type
        const SM: usize, // Source rows (== dest cols)
        const DM: usize, // Destination rows (== source cols)
    >()
    where
        Boolean: Vectorizable<SM>,
        <Boolean as Vectorizable<SM>>::Array: BooleanArray,
        SR: BooleanArray,
        BitDecomposed<AdditiveShare<Boolean, SM>>:
            for<'a> TransposeFrom<&'a Vec<AdditiveShare<SR>>, Error = LengthError>,
        Standard: Distribution<SR>,
    {
        let t_impl = |src| {
            let mut dst =
                BitDecomposed::try_from(vec![AdditiveShare::<Boolean, SM>::ZERO; DM]).unwrap();
            dst.transpose_from(src).ok().unwrap();
            dst
        };

        let step = min(SM, DM);
        let m = ba_shares_test_matrix::<SR, SM, DM>(step).to_vec();
        let m_t = t_impl(&m);
        assert_eq!(&*m_t, &bool_shares_test_matrix::<DM, SM>(step));

        let mut left_rng = thread_rng();
        let mut right_rng = thread_rng();
        let m = repeat_with(|| AdditiveShare::from_fns(|_| left_rng.gen(), |_| right_rng.gen()))
            .take(SM)
            .collect::<Vec<_>>();
        let m_t = t_impl(&m);

        #[rustfmt::skip]
        verify_transpose(SM, DM,
            |i, j| (m_t[i].left_arr().get(j).unwrap(), m_t[i].right_arr().get(j).unwrap()),
            |i, j| (m[i].get(j).unwrap().left(), m[i].get(j).unwrap().right()),
        );
    }

    // The order of type parameters matches the implementation macro: BA<n>, <m>, <n>
    pub(super) fn test_transpose_shares_ba_fn_to_bool<
        SR,              // Source row type
        const SM: usize, // Source rows (== dest cols)
        const DM: usize, // Destination rows (== source cols)
    >()
    where
        Boolean: Vectorizable<SM>,
        <Boolean as Vectorizable<SM>>::Array: BooleanArray,
        SR: BooleanArray,
        [AdditiveShare<Boolean, SM>; DM]:
            for<'a> TransposeFrom<&'a dyn Fn(usize) -> AdditiveShare<SR>, Error = Infallible>,
        Standard: Distribution<SR>,
    {
        let t_impl = |src| {
            let mut dst = [AdditiveShare::<Boolean, SM>::ZERO; DM];
            dst.transpose_from(src).unwrap_infallible();
            dst
        };

        let step = min(SM, DM);
        let m = ba_shares_test_matrix::<SR, SM, DM>(step);
        let m_func = |i| AdditiveShare::<SR>::clone(&m[i]);
        let m_t = t_impl(&m_func);
        assert_eq!(m_t, bool_shares_test_matrix::<DM, SM>(step));

        let mut left_rng = thread_rng();
        let mut right_rng = thread_rng();
        let m = repeat_with(|| AdditiveShare::from_fns(|_| left_rng.gen(), |_| right_rng.gen()))
            .take(SM)
            .collect::<Vec<_>>();
        let m_func = |i| AdditiveShare::<SR>::clone(&m[i]);
        let m_t = t_impl(&m_func);

        #[rustfmt::skip]
        verify_transpose(SM, DM,
            |i, j| (m_t[i].left_arr().get(j).unwrap(), m_t[i].right_arr().get(j).unwrap()),
            |i, j| (m[i].get(j).unwrap().left(), m[i].get(j).unwrap().right()),
        );
    }

    // The order of type parameters matches the implementation macro: BA<m>, <m>, <n>
    pub(super) fn test_transpose_shares_bool_to_ba<
        DR,              // Destination row type
        const SM: usize, // Source rows (== dest cols)
        const DM: usize, // Destination rows (== source cols)
    >()
    where
        Boolean: Vectorizable<DM>,
        <Boolean as Vectorizable<DM>>::Array: BooleanArray,
        DR: BooleanArray,
        [AdditiveShare<DR>; DM]:
            for<'a> TransposeFrom<&'a [AdditiveShare<Boolean, DM>; SM], Error = Infallible>,
    {
        let t_impl = |src| {
            let mut dst = [AdditiveShare::<DR>::ZERO; DM];
            dst.transpose_from(src).unwrap_infallible();
            dst
        };

        let step = min(SM, DM);
        let m = bool_shares_test_matrix::<SM, DM>(step);
        let m_t = t_impl(&m);
        assert_eq!(m_t, ba_shares_test_matrix::<DR, DM, SM>(step));

        let mut left_rng = thread_rng();
        let mut right_rng = thread_rng();
        let m = repeat_with(|| AdditiveShare::from_fns(|_| left_rng.gen(), |_| right_rng.gen()))
            .take(SM)
            .collect::<Vec<_>>();
        let m_t = t_impl(<&[AdditiveShare<Boolean, DM>; SM]>::try_from(m.as_slice()).unwrap());

        #[rustfmt::skip]
        verify_transpose(SM, DM,
            |i, j| (m_t[i].get(j).unwrap().left(), m_t[i].get(j).unwrap().right()),
            |i, j| (m[i].left_arr().get(j).unwrap(), m[i].right_arr().get(j).unwrap()),
        );
    }

    pub(super) fn test_aggregation_transpose<
        const SM: usize, // Source rows (== dest cols)
        const DM: usize, // Destination rows (== source cols)
    >()
    where
        Boolean: Vectorizable<SM> + Vectorizable<DM>,
        <Boolean as Vectorizable<SM>>::Array: BooleanArray,
        <Boolean as Vectorizable<DM>>::Array: BooleanArray,
        Vec<BitDecomposed<AdditiveShare<Boolean, SM>>>: for<'a> TransposeFrom<
            &'a [BitDecomposed<AdditiveShare<Boolean, DM>>],
            Error = Infallible,
        >,
    {
        let step = min(SM, DM);

        // For most transpose tests, we do a test of a structured matrix, and then a test of a random matrix.
        // For this test, we pack the structured and random matrices together as the two bits of trigger
        // value. We then transpose both at once using the aggregation transpose.
        let m0 = bool_shares_test_matrix::<SM, DM>(step);
        let mut left_rng = thread_rng();
        let mut right_rng = thread_rng();
        let m1 = repeat_with(|| AdditiveShare::from_fns(|_| left_rng.gen(), |_| right_rng.gen()))
            .take(SM)
            .collect::<Vec<_>>();

        let mut m = Vec::with_capacity(SM);
        for (row0, row1) in zip(m0, m1.clone()) {
            m.push(BitDecomposed::new([row0, row1]));
        }

        let mut m_t = Vec::<BitDecomposed<AdditiveShare<Boolean, SM>>>::new();
        m_t.transpose_from(&m).unwrap_infallible();

        let (m_t0, m_t1): (Vec<_>, Vec<_>) = m_t
            .into_iter()
            .map(|bits_and_rows| {
                assert_eq!(bits_and_rows.len(), 2);
                let mut br = bits_and_rows.into_iter();
                (br.next().unwrap(), br.next().unwrap())
            })
            .unzip();

        assert_eq!(m_t0, bool_shares_test_matrix::<DM, SM>(step));

        #[rustfmt::skip]
        verify_transpose(SM, DM,
            |i, j| (m_t1[i].left_arr().get(j).unwrap(), m_t1[i].right_arr().get(j).unwrap()),
            |i, j| (m1[i].left_arr().get(j).unwrap(), m1[i].right_arr().get(j).unwrap()),
        );
    }
}
