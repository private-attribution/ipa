use std::{
    fmt::{Debug, Formatter},
    ops::Index,
};

use bitvec::{
    array::BitArray,
    prelude::{bitarr, BitArr, Lsb0},
};
use generic_array::GenericArray;
use subtle::{Choice, ConstantTimeEq};
use typenum::{Unsigned, U1, U2, U3, U4, U5};

use crate::{
    error::LengthError,
    ff::{boolean_array::NonZeroPadding, Field, MultiplyAccumulate, Serializable, U128Conversions},
    impl_serializable_trait, impl_shared_value_common,
    protocol::prss::FromRandomU128,
    secret_sharing::{Block, FieldVectorizable, SharedValue, StdArray, Vectorizable},
};

/// Trait for data types storing arbitrary number of bits.
pub trait GaloisField:
    Field + Into<u128> + Index<usize, Output = bool> + Index<u32, Output = bool>
{
    const POLYNOMIAL: u128;

    fn as_u128(self) -> u128 {
        <Self as Into<u128>>::into(self)
    }
}

// Bit store type definitions
type U8_1 = BitArr!(for 8, in u8, Lsb0);
type U8_2 = BitArr!(for 9, in u8, Lsb0);
type U8_3 = BitArr!(for 24, in u8, Lsb0);
type U8_4 = BitArr!(for 32, in u8, Lsb0);
type U8_5 = BitArr!(for 40, in u8, Lsb0);

impl Block for U8_1 {
    type Size = U1;
}

impl Block for U8_2 {
    type Size = U2;
}

impl Block for U8_3 {
    type Size = U3;
}

impl Block for U8_4 {
    type Size = U4;
}

impl Block for U8_5 {
    type Size = U5;
}

/// The implementation below cannot be constrained without breaking Rust's
/// macro processor.  This noop ensures that the instance of `GenericArray` used
/// is `Copy`.  It should be - it's the same size as the `BitArray` instance.
fn assert_copy<C: Copy>(c: C) -> C {
    c
}

#[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
mod clmul_x86_64 {
    use core::arch::x86_64::{__m128i, _mm_clmulepi64_si128, _mm_extract_epi64, _mm_set_epi64x};

    #[inline]
    unsafe fn clmul(a: u64, b: u64) -> __m128i {
        #[allow(clippy::cast_possible_wrap)] // Thanks Intel.
        unsafe fn to_m128i(v: u64) -> __m128i {
            _mm_set_epi64x(0, v as i64)
        }
        _mm_clmulepi64_si128(to_m128i(a), to_m128i(b), 0)
    }

    #[allow(clippy::cast_sign_loss)] // Thanks Intel.
    #[inline]
    unsafe fn extract<const I: i32>(v: __m128i) -> u128 {
        // Note: watch for sign extension that you get from casting i64 to u128 directly.
        u128::from(_mm_extract_epi64(v, I) as u64)
    }

    /// clmul with 32-bit inputs (and a 64-bit answer).
    #[inline]
    pub unsafe fn clmul32(a: u64, b: u64) -> u128 {
        extract::<0>(clmul(a, b))
    }

    /// clmul with 64-bit inputs (and a 128-bit answer).
    #[inline]
    pub unsafe fn clmul64(a: u64, b: u64) -> u128 {
        let product = clmul(a, b);
        extract::<1>(product) << 64 | extract::<0>(product)
    }
}

#[allow(unreachable_code)]
#[inline]
fn clmul<GF: GaloisField>(a: GF, b: GF) -> u128 {
    #[allow(clippy::cast_possible_truncation)] // Asserts will catch this later.
    fn to_u64<GF: GaloisField>(x: GF) -> u64 {
        x.as_u128() as u64
    }
    let (a, b) = (to_u64(a), to_u64(b));

    #[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
    return if GF::BITS <= 32 {
        unsafe { clmul_x86_64::clmul32(a, b) }
    } else if GF::BITS <= 64 {
        unsafe { clmul_x86_64::clmul64(a, b) }
    } else {
        unreachable!("Galois fields with more than 64 bits not supported");
    };

    debug_assert!(
        2 * GF::BITS <= u128::BITS,
        "Galois fields with more than 64 bits not supported"
    );

    #[cfg(all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_feature = "aes"
    ))]
    return unsafe { core::arch::aarch64::vmull_p64(a, b) };

    let a = u128::from(a);
    let mut product = 0;
    for i in 0..GF::BITS {
        let bit = u128::from(b >> i & 1);
        product ^= bit * (a << i);
    }
    product
}

macro_rules! bit_array_impl {
    ( $modname:ident, $name:ident, $store:ty, $bits:expr, $one:expr, $polynomial:expr, $deser_type: tt, $({$($extra:item)*})? ) => {
        #[allow(clippy::suspicious_arithmetic_impl)]
        #[allow(clippy::suspicious_op_assign_impl)]
        mod $modname {
            use super::*;

            /// N-bit array of bits. It supports boolean algebra, and provides access
            /// to individual bits via index.
            ///
            /// Bits are stored in the Little-Endian format. Accessing the first element
            /// like `b[0]` will return the LSB.
            #[derive(Clone, Copy, PartialEq, Eq)]
            pub struct $name($store);

            impl Default for $name {
                fn default() -> Self {
                    Self::ZERO
                }
            }

            impl SharedValue for $name {
                type Storage = $store;
                const BITS: u32 = $bits;
                const ZERO: Self = Self(<$store>::ZERO);

                impl_shared_value_common!();
            }

            impl Vectorizable<1> for $name {
                type Array = crate::secret_sharing::StdArray<$name, 1>;
            }

            impl FieldVectorizable<1> for $name {
                type ArrayAlias = crate::secret_sharing::StdArray<$name, 1>;
            }

            impl Field for $name {
                const NAME: &'static str = stringify!($field);

                const ONE: Self = Self($one);
            }

            // Note: The multiply-accumulate tests are not currently instantiated for Galois fields.
            impl MultiplyAccumulate for $name {
                type Accumulator = $name;
                type AccumulatorArray<const N: usize> = [$name; N];
            }

            impl U128Conversions for $name {
                fn as_u128(&self) -> u128 {
                    (*self).into()
                }

                fn truncate_from<T: Into<u128>>(v: T) -> Self {
                    const MASK: u128 = u128::MAX >> (u128::BITS - <$name>::BITS);
                    let v = &(v.into() & MASK).to_le_bytes()[..<Self as Serializable>::Size::to_usize()];
                    Self(<$store>::new(v.try_into().unwrap()))
                }
            }

            /// This function generates a Galois field element from a raw slice.
            /// When the length of the slice is smaller than the byte length
            /// of an element, the remaining bytes are filled with Zeros.
            ///
            /// ## Errors
            /// Returns an error when the slice is too long.
            ///
            /// ## Panics
            /// Panics when `u32` to `usize` conversion fails
            impl TryFrom<&[u8]> for $name {
                type Error = LengthError;

                fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                    if value.len()<=usize::try_from(Self::BITS/8).unwrap() {
                        let mut bitarray = [0u8;{($bits+7)/8}];
                        bitarray[0..value.len()].copy_from_slice(value);
                        Ok($name(BitArray::<[u8;{($bits+7)/8}],Lsb0>::new(bitarray)))
                    } else {
                        Err(LengthError {
                            expected: usize::try_from(Self::BITS).unwrap(),
                            actual: value.len(),
                        })
                    }
                }
            }

            impl FromRandomU128 for $name {
                fn from_random_u128(src: u128) -> Self {
                    U128Conversions::truncate_from(src)
                }
            }

            impl GaloisField for $name {
                const POLYNOMIAL: u128 = $polynomial;
            }

            // If the field value fits in a machine word, a naive comparison should be fine.
            // But this impl is important for `[T]`, and useful to document where a
            // constant-time compare is intended.
            impl ConstantTimeEq for $name {
                fn ct_eq(&self, other: &Self) -> Choice {
                    // Note that this will compare the padding bits. That should not be
                    // a problem, because we should not allow the padding bits to become
                    // non-zero.
                    self.0.as_raw_slice().ct_eq(&other.0.as_raw_slice())
                }
            }

            impl rand::distributions::Distribution<$name> for rand::distributions::Standard {
                fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> $name {
                    <$name>::truncate_from(rng.gen::<u128>())
                }
            }

            // Addition in Galois fields.
            //
            // You can think of its structure as similar to polynomials, where all of the coefficients belong to the original field;
            // meaning they are either 0 or 1.
            //
            // Here's an example in GF(2^8)
            // Let a = x^7 + x^4 + x + 1
            // We will write that as 10010011
            // (big-endian notation, where each bit is a coefficient from the polynomial)
            //
            // Let b = x^7 + x^6 + x^3 + x
            // We will write that as 11001010
            //
            // Addition of polynomials is trivial.
            // (x^7 + x^4 + x + 1) + (x^7 + x^6 + x^3 + x)
            // = x^6 + x^4 + x^3 + 1
            // = 01011001
            // Since the coefficients are in GF(2), we can just XOR these bitwise representations.
            // Note for x^7 + x^7 = 0 because 1 + 1 = 0 in GF(2)
            impl <'a, 'b> std::ops::Add<&'b $name> for &'a $name {
                type Output = $name;
                fn add(self, rhs: &'b $name) -> Self::Output {
                    $name(self.0 ^ rhs.0)
                }
            }

            impl std::ops::Add<&$name> for $name {
                type Output = Self;
                fn add(self, rhs: &$name) -> Self::Output {
                    std::ops::Add::add(&self, rhs)
                }
            }

            impl std::ops::Add<$name> for &$name {
                type Output = $name;
                fn add(self, rhs: $name) -> Self::Output {
                    std::ops::Add::add(self, &rhs)
                }
            }

            impl std::ops::Add<$name> for $name {
                type Output = Self;
                fn add(self, rhs: $name) -> Self::Output {
                    std::ops::Add::add(&self, &rhs)
                }
            }

            impl std::ops::AddAssign for $name {
                fn add_assign(&mut self, rhs: Self) {
                    *self.0.as_mut_bitslice() ^= rhs.0;
                }
            }

            impl std::ops::Sub for $name {
                type Output = Self;
                fn sub(self, rhs: Self) -> Self::Output {
                    self + rhs
                }
            }

            impl std::ops::SubAssign for $name {
                fn sub_assign(&mut self, rhs: Self) {
                    *self += rhs;
                }
            }

            // This is an implementation of a Galois field.
            // A Galois field of order 2^8 is often written as GF(2^8)
            //
            // Multiplication is a bit more complex:
            //
            // First we need to perform "bitwise multiplication" of the two numbers:
            //            10010011
            //          x 11001010
            //         -----------
            //            00000000
            //           10010011
            //          00000000
            //         10010011
            //        00000000
            //       00000000
            //      10010011
            //   + 10010011
            //   -----------------
            //     110100011111110
            //
            // Notice that addition here is just XOR, there are no carries. Think about the analogy to polynomials:
            //
            // The first part, where the original bit sequence is just bit-shifted can be conceptualized as distributing terms:
            // (x^7 + x^4 + x + 1) * (x^7 + x^6 + x^3 + x)
            //
            // Next, the terms of a given order are combined by adding the coefficients (in this case mod 2).
            // There are no "carries" here, since adding x^6 + x^6 does not yield x^7.
            //
            // So the answer is:
            // x^14 + x^13 + 0 + x^11 + 0 + 0 + 0 + x^7 + x^6 + x^5 + x^4 + x^3 + x^2 + x + 0
            //
            // Finally, we need to reduce this polynomial to something of the same size as the original inputs.
            // For this, we use an irreducible polynomial of order 8. Let's say we've chosen x^8 + x^4 + x^3 + x + 1
            // Any irreducible polynomial of order 8 will do, but this is the one we've chosen as a constant for our implementation of GF(2^8)
            //
            // We assume that: x^8 + x^4 + x^3 + x + 1 = 0
            //
            // Now there are roots of this polynomial, but no *real* roots, only complex roots. Let's call one of those roots α.
            // Our Galois field is really represented by polynomials of α. So our input a was:
            // α^7 + α^4 + α + 1
            //
            // Since we know that x^8 + x^4 + x^3 + x + 1 = 0, we can distribute out terms of this structure and replace them with zero.
            //
            // So the result of our multiplication was:
            // 110100011111110
            // which you can think of as:
            // x^14 + x^13 + 0 + x^11 + 0 + 0 + 0 + x^7 + x^6 + x^5 + x^4 + x^3 + x^2 + x + 0
            //
            // We start by reducing the degree of the highest order element.
            // We know that x^6 * (x^8 + x^4 + x^3 + x + 1) = 0, so we can subtract this value without changing anything
            //
            // The result is the same as
            //      110100011111110
            //  XOR 10001101
            //
            // Basically just bit-shift the irreducible polynomial up 6 bits and XOR it.
            //
            // We can continue this process until we have reached a polynomial where all terms are less than x^8.
            //
            // This defines a field, since all of the following properties hold:
            //
            // 1. Closure: For any two elements a and b in the field, a+b and ab are also in the field.
            // 2. Associativity: Addition and multiplication are both associative, meaning that (a+b)+c = a+(b+c) and (ab)c = a(bc) for any elements a,b, and c in the field.
            // 3. Commutativity: Addition and multiplication are both commutative, meaning that a+b = b+a and ab = ba for any elements a and b in the field.
            // 4. Identity elements: There exist unique elements 0 and 1 in the field such that for any element a in the field, a+0 = a and a×1 = a.
            // 5. Inverse elements: For any non-zero element a in the field, there exists a unique element -a such that a+(-a) = 0, and there exists a unique element a^(-1) such that a×a^(-1) = 1.
            // 6. Distributivity: Multiplication distributes over addition, meaning that a(b+c) = ab+ac for any elements a, b, and c in the field.
            //
            // Tests of Associativity, Commutativity and Distributivity are below.
            impl std::ops::Mul for $name {
                type Output = Self;
                fn mul(self, rhs: Self) -> Self::Output {
                    let mut product = clmul(self, rhs);
                    for i in (0..(Self::BITS - 1)).into_iter().rev() {
                        let b = product >> (Self::BITS + i);
                        product ^= (<Self as GaloisField>::POLYNOMIAL * b) << i;
                    }
                    Self::try_from(product).unwrap()
                }
            }

            impl std::ops::MulAssign for $name {
                fn mul_assign(&mut self, rhs: Self) {
                    *self = *self * rhs;
                }
            }

            impl std::ops::Neg for $name {
                type Output = Self;
                fn neg(self) -> Self::Output {
                    Self(self.0)
                }
            }

            impl TryFrom<u128> for $name {
                type Error = crate::error::Error;

                /// Fallible conversion from `u128` to this data type. The input value must
                /// be at most `Self::BITS` long. That is, the integer value must be less than
                /// or equal to `2^Self::BITS`, or it will return an error.
                fn try_from(v: u128) -> Result<Self, Self::Error> {
                    if u128::BITS - v.leading_zeros() <= Self::BITS {
                        Ok(Self::truncate_from(v))
                    } else {
                        Err(crate::error::Error::FieldValueTruncation(format!(
                            "Bit array size {} is too small to hold the value {}.",
                            Self::BITS,
                            v
                        )))
                    }
                }
            }

            impl From<$name> for $store {
                fn from(v: $name) -> Self {
                    v.0
                }
            }

            #[allow(clippy::from_over_into)]
            impl Into<u128> for $name {
                /// Infallible conversion from this data type to `u128`. We assume that the
                /// inner value is at most 128-bit long. That is, the integer value must be
                /// less than or equal to `2^Self::BITS`. Should be long enough for our use
                /// case.
                fn into(self) -> u128 {
                    debug_assert!(<$name>::BITS <= 128);
                    self
                        .0
                        .iter()
                        .by_refs()
                        .enumerate()
                        .fold(0_u128, |acc, (i, b)| acc + (u128::from(*b) << i))
                }
            }

            impl std::ops::Index<usize> for $name {
                type Output = bool;

                fn index(&self, index: usize) -> &Self::Output {
                    debug_assert!(index < usize::try_from(<$name>::BITS).unwrap());
                    &self.0.as_bitslice()[index]
                }
            }

            impl std::ops::Index<u32> for $name {
                type Output = bool;

                fn index(&self, index: u32) -> &Self::Output {
                    debug_assert!(index < <$name>::BITS);
                    &self[index as usize]
                }
            }

            /// Compares two Galois Field elements by their representational ordering
            ///
            /// The original implementation of `Ord` for `bitvec::BitArray` compares two arrays
            /// from LSB, and at the first index where the arrays differ, the array with the high
            /// bit is greater. For our use case, however, we want to compare two arrays by their
            /// integer values represented by the bits. In other words, if `a < b` is true, then
            /// `BitArray::try_from(a).unwrap() < BitArray::try_from(b).unwrap()` must also be true.
            impl Ord for $name {
                fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                    <$name as Into<u128>>::into(*self).cmp(&<$name as Into<u128>>::into(*other))
                }
            }

            impl PartialOrd for $name {
                fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                    Some(self.cmp(other))
                }
            }

            impl_serializable_trait!($name, $bits, $store, $deser_type);

            impl Debug for $name {
                fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                    write!(f, concat!(stringify!($name), "_{v:0", $bits, "b}"), v = self.as_u128())
                }
            }

            #[cfg(all(test, unit_test))]
            mod tests {
                use super::*;
                use crate::{ff::GaloisField, secret_sharing::SharedValue};
                use rand::{thread_rng, Rng};

                const MASK: u128 = u128::MAX >> (u128::BITS - <$name>::BITS);

                #[test]
                pub fn basic() {
                    let zero = bitarr!(u8, Lsb0; 0; <$name>::BITS as usize);
                    let mut one = bitarr!(u8, Lsb0; 0; <$name>::BITS as usize);
                    *one.first_mut().unwrap() = true;
                    assert_eq!($name::default(), $name::ZERO);
                    assert_eq!($name::ZERO.0, zero);
                    assert_eq!($name::ONE.0, one);
                    assert_eq!($name::truncate_from(1_u128).0, one);

                    let max_plus_one = (1_u128 << <$name>::BITS) + 1;
                    assert!($name::try_from(max_plus_one).is_err());
                    assert_eq!($name::truncate_from(max_plus_one).0, one);
                }

                #[test]
                pub fn index() {
                    let s = $name::try_from(1_u128).unwrap();
                    assert_eq!(s[0_usize], true);
                }

                #[test]
                #[cfg(debug_assertions)]
                #[should_panic(expected = "index < usize::try_from")]
                pub fn out_of_count_index() {
                    // With debug assertions enabled, this test will panic on any out-of-bounds
                    // access. Without debug assertions, it will not panic on access to the unused
                    // bits for non-multiple-of-8 bitwidths. Enable the test only with debug
                    // assertions, rather than try to do something conditioned on the bit width.

                    let s = $name::try_from(1_u128).unwrap();
                    // Below assert doesn't matter. The indexing should panic
                    assert_eq!(s[<$name>::BITS as usize], false);
                }

                #[test]
                pub fn basic_ops() {
                    let mut rng = thread_rng();
                    let a = rng.gen::<u128>();
                    let b = rng.gen::<u128>();

                    let xor = $name::truncate_from(a ^ b);

                    let a = $name::truncate_from(a);
                    let b = $name::truncate_from(b);

                    assert_eq!(a + b, xor);
                    assert_eq!(a - b, xor);
                    assert_eq!(-a, a);
                    assert_eq!(a + (-a), $name::ZERO);
                }

                #[test]
                pub fn polynomial_bits() {
                    assert_eq!($name::BITS + 1, u128::BITS - $name::POLYNOMIAL.leading_zeros(),
                               "The polynomial should have one more bit than the field.");
                }

                #[test]
                pub fn distributive_property_of_multiplication() {
                    let mut rng = thread_rng();
                    let a = $name::truncate_from(rng.gen::<u128>());
                    let b = $name::truncate_from(rng.gen::<u128>());
                    let r = $name::truncate_from(rng.gen::<u128>());
                    let a_plus_b = a + b;
                    let r_a_plus_b = r * a_plus_b;
                    assert_eq!(r_a_plus_b, r * a + r * b, "distributive {r:?}*({a:?}+{b:?})");
                }

                #[test]
                pub fn commutative_property_of_multiplication() {
                    let mut rng = thread_rng();
                    let a = $name::truncate_from(rng.gen::<u128>());
                    let b = $name::truncate_from(rng.gen::<u128>());
                    let ab = a * b;
                    // This stupid hack is here to FORCE the compiler to not just optimize this away and really run the test
                    let b_copy = $name::truncate_from(b.as_u128());
                    let ba = b_copy * a;
                    assert_eq!(ab, ba, "commutative {a:?}*{b:?}");
                }

                #[test]
                pub fn associative_property_of_multiplication() {
                    let mut rng = thread_rng();
                    let a = $name::truncate_from(rng.gen::<u128>());
                    let b = $name::truncate_from(rng.gen::<u128>());
                    let c = $name::truncate_from(rng.gen::<u128>());
                    let bc = b * c;
                    let ab = a * b;
                    assert_eq!(a * bc, ab * c, "associative {a:?}*{b:?}*{c:?}");
                }

                #[test]
                pub fn conversion() {
                    let max = $name::try_from(MASK).unwrap();

                    assert_eq!(
                        <$name as Into<u128>>::into(max),
                        MASK,
                    );
                }

                #[test]
                pub fn ordering() {
                    let mut rng = thread_rng();
                    let a = rng.gen::<u128>() & MASK;
                    let b = rng.gen::<u128>() & MASK;

                    println!("a: {a}");
                    println!("b: {b}");

                    assert_eq!(a < b, $name::truncate_from(a) < $name::truncate_from(b));
                }

                #[test]
                pub fn serde() {
                    let mut rng = thread_rng();
                    let a = rng.gen::<u128>() & MASK;
                    let a = $name::truncate_from(a);

                    let mut buf = GenericArray::default();
                    a.clone().serialize(&mut buf);

                    assert_eq!(a, $name::deserialize(&buf).unwrap(), "failed to serialize/deserialize {a:?}");
                }

                #[test]
                fn slice_to_galois_err() {
                    let mut rng = thread_rng();
                    let vec = (0..{(<$name>::BITS+7)/8+1}).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();
                    let element = <$name>::try_from(vec.as_slice());
                    assert_eq!(
                        element.unwrap_err(),
                        LengthError {
                            expected: <$name>::BITS as usize,
                            actual: ((<$name>::BITS + 7) / 8 + 1) as usize,
                        },
                    );
                }
            }

            $( $( $extra )* )?
        }

        pub use $modname::$name;
    };
}

bit_array_impl!(
    bit_array_40,
    Gf40Bit,
    U8_5,
    40,
    bitarr!(const u8, Lsb0; 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    // x^40 + x^5 + x^3 + x^2 + 1
    0b1_0000_0000_0000_0000_0000_0000_0000_0000_0010_1101_u128,
    infallible,
);

bit_array_impl!(
    bit_array_32,
    Gf32Bit,
    U8_4,
    32,
    bitarr!(const u8, Lsb0; 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    // x^32 + x^7 + x^3 + x^2 + 1
    0b1_0000_0000_0000_0000_0000_0000_1000_1101_u128,
    infallible,
);

impl Vectorizable<32> for Gf32Bit {
    type Array = StdArray<Self, 32>;
}

impl FieldVectorizable<32> for Gf32Bit {
    type ArrayAlias = StdArray<Self, 32>;
}

bit_array_impl!(
    bit_array_20,
    Gf20Bit,
    U8_3,
    20,
    bitarr!(const u8, Lsb0; 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    // x^20 + x^7 + x^3 + x^2 + 1
    0b1_0000_0000_0000_1000_1101_u128,
    fallible,
);

bit_array_impl!(
    bit_array_8,
    Gf8Bit,
    U8_1,
    8,
    bitarr!(const u8, Lsb0; 1, 0, 0, 0, 0, 0, 0, 0),
    // x^8 + x^4 + x^3 + x + 1
    0b1_0001_1011_u128,
    infallible,
);

bit_array_impl!(
    bit_array_9,
    Gf9Bit,
    U8_2,
    9,
    bitarr!(const u8, Lsb0; 1, 0, 0, 0, 0, 0, 0, 0, 0),
    // x^9 + x^4 + x^3 + x + 1
    0b10_0001_1011_u128,
    fallible,
);

bit_array_impl!(
    bit_array_3,
    Gf3Bit,
    U8_1,
    3,
    bitarr!(const u8, Lsb0; 1, 0, 0),
    // x^3 + x + 1
    0b1_011_u128,
    fallible,
);

bit_array_impl!(
    bit_array_1,
    Gf2,
    U8_1,
    1,
    bitarr!(const u8, Lsb0; 1),
    // x
    0b10_u128,
    fallible,
    {
        impl From<bool> for Gf2 {
            fn from(value: bool) -> Self {
                let mut v = Gf2::ZERO;
                v.0.set(0, value);
                v
            }
        }
    }
);
