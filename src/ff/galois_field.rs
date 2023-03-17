use crate::{
    ff::{Field, Serializable},
    secret_sharing::{Block, SharedValue},
};
use bitvec::prelude::{bitarr, BitArr, Lsb0};
use generic_array::GenericArray;
use std::ops::Index;
use typenum::{Unsigned, U1, U4, U5};

/// Trait for data types storing arbitrary number of bits.
pub trait GaloisField:
    Field + Into<u128> + Index<usize, Output = bool> + Index<u32, Output = bool>
{
    const POLYNOMIAL: u128;

    fn as_u128(self) -> u128 {
        <Self as Into<u128>>::into(self)
    }

    /// Truncates the higher-order bits larger than `Self::BITS`, and converts
    /// into this data type. This conversion is lossy. Callers are encouraged
    /// to use `try_from` if the input is not known in advance.
    fn truncate_from<T: Into<u128>>(v: T) -> Self;
}

// Bit store type definitions
type U8_1 = BitArr!(for 8, in u8, Lsb0);
type U8_4 = BitArr!(for 32, in u8, Lsb0);
type U8_5 = BitArr!(for 40, in u8, Lsb0);

impl Block for U8_1 {
    type Size = U1;
    const VALID_BIT_LENGTH: u32 = 8;
}

impl Block for U8_4 {
    type Size = U4;
    const VALID_BIT_LENGTH: u32 = 32;
}

impl Block for U8_5 {
    type Size = U5;
    const VALID_BIT_LENGTH: u32 = 40;
}

/// The implementation below cannot be constrained without breaking Rust's
/// macro processor.  This noop ensures that the instance of `GenericArray` used
/// is `Copy`.  It should be - it's the same size as the `BitArray` instance.
fn assert_copy<C: Copy>(c: C) -> C {
    c
}

macro_rules! bit_array_impl {
    ( $modname:ident, $name:ident, $store:ty, $one:expr, $polynomial:expr ) => {
        #[allow(clippy::suspicious_arithmetic_impl)]
        #[allow(clippy::suspicious_op_assign_impl)]
        mod $modname {
            use super::*;

            /// N-bit array of bits. It supports boolean algebra, and provides access
            /// to individual bits via index.
            ///
            /// Bits are stored in the Little-Endian format. Accessing the first element
            /// like `b[0]` will return the LSB.
            #[derive(std::fmt::Debug, Clone, Copy, PartialEq, Eq)]
            pub struct $name($store);

            impl SharedValue for $name {
                type Storage = $store;
                const BITS: u32 = <$store as Block>::VALID_BIT_LENGTH;
                const ZERO: Self = Self(<$store>::ZERO);
            }

            impl Field for $name {
                const ONE: Self = Self($one);

                fn as_u128(&self) -> u128 {
                    (*self).into()
                }
            }

            impl GaloisField for $name {
                const POLYNOMIAL: u128 = $polynomial;

                fn truncate_from<T: Into<u128>>(v: T) -> Self {
                    let v = &v.into().to_le_bytes()[..<Self as Serializable>::Size::to_usize()];
                    Self(<$store>::new(v.try_into().unwrap()))
                }
            }

            // TODO (taikiy): Remove this infallible conversion and bring back to TryFrom
            impl From<u128> for $name {
                fn from(v: u128) -> Self {
                    Self::truncate_from(v)
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
            impl std::ops::Add for $name {
                type Output = Self;
                fn add(self, rhs: Self) -> Self::Output {
                    Self(self.0 ^ rhs.0)
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
            // So the result of our multipliation was:
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
                    debug_assert!(2 * Self::BITS < u128::BITS);
                    let a = <Self as GaloisField>::as_u128(self);
                    let mut product = 0;
                    for i in 0..Self::BITS {
                        let bit = u128::from(rhs[i]);
                        product ^= bit * (a << i);
                    }

                    let poly = <Self as GaloisField>::POLYNOMIAL;
                    while (u128::BITS - product.leading_zeros()) > Self::BITS {
                        let bits_to_shift = poly.leading_zeros() - product.leading_zeros();
                        product ^= (poly << bits_to_shift);
                    }

                    <Self as GaloisField>::truncate_from(product)
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
                        .fold(0_u128, |acc, (i, b)| acc + ((*b as u128) << i))
                }
            }

            impl std::ops::Index<usize> for $name {
                type Output = bool;

                fn index(&self, index: usize) -> &Self::Output {
                    &self.0.as_bitslice()[index]
                }
            }

            impl std::ops::Index<u32> for $name {
                type Output = bool;

                fn index(&self, index: u32) -> &Self::Output {
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

            impl Serializable for $name {
                type Size = <$store as Block>::Size;

                fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
                    buf.copy_from_slice(self.0.as_raw_slice());
                }

                fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
                    Self(<$store>::new(assert_copy(*buf).into()))
                }
            }

            #[cfg(all(test, not(feature = "shuttle")))]
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

                    assert_eq!($name::ZERO.0, zero);
                    assert_eq!($name::ONE.0, one);
                    assert_eq!($name::truncate_from(1_u128).0, one);

                    let max_plus_one = (1_u128 << <$name>::BITS) + 1;
                    // TODO (taikiy): Uncomment this line once TryFrom is back
                    // assert!($name::try_from(max_plus_one).is_err());
                    assert_eq!(
                        $name::try_from(max_plus_one & MASK).unwrap().0,
                        one
                    );

                    assert_eq!($name::truncate_from(max_plus_one).0, one);
                }

                #[test]
                pub fn index() {
                    let s = $name::try_from(1_u128).unwrap();
                    assert_eq!(s[0_usize], true);
                    assert_eq!(s[(<$name>::BITS - 1) as u32], false);
                }

                #[test]
                #[should_panic]
                pub fn out_of_count_index() {
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
                pub fn distributive_property_of_multiplication() {
                    let mut rng = thread_rng();
                    let a = $name::truncate_from(rng.gen::<u128>());
                    let b = $name::truncate_from(rng.gen::<u128>());
                    let r = $name::truncate_from(rng.gen::<u128>());
                    let a_plus_b = a + b;
                    let r_a_plus_b = r * a_plus_b;
                    assert_eq!(r_a_plus_b, r * a + r * b);
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
                    assert_eq!(ab, ba);
                }

                #[test]
                pub fn associative_property_of_multiplication() {
                    let mut rng = thread_rng();
                    let a = $name::truncate_from(rng.gen::<u128>());
                    let b = $name::truncate_from(rng.gen::<u128>());
                    let c = $name::truncate_from(rng.gen::<u128>());
                    let bc = b * c;
                    let ab = a * b;
                    assert_eq!(a * bc, ab * c);
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

                    assert_eq!(a, $name::deserialize(&buf));
                }
            }
        }

        pub use $modname::$name;
    };
}

bit_array_impl!(
    bit_array_40,
    Gf40Bit,
    U8_5,
    bitarr!(const u8, Lsb0; 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    // x^40 + x^5 + x^3 + x^2 + 1
    0b1_0000_0000_0000_0000_0000_0000_0000_0000_0010_1101_u128
);

bit_array_impl!(
    bit_array_32,
    Gf32Bit,
    U8_4,
    bitarr!(const u8, Lsb0; 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    // x^32 + x^7 + x^3 + x^2 + 1
    0b1_0000_0000_0000_0000_0000_0000_1000_1101_u128
);

bit_array_impl!(
    bit_array_8,
    Gf8Bit,
    U8_1,
    bitarr!(const u8, Lsb0; 1, 0, 0, 0, 0, 0, 0, 0),
    // x^8 + x^4 + x^3 + x + 1
    0b1_0001_1011_u128
);
