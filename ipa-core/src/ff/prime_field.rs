use std::{fmt::Display, mem};

use generic_array::GenericArray;

use super::Field;
use crate::{
    const_assert,
    ff::{Serializable, U128Conversions},
    impl_shared_value_common,
    protocol::prss::FromRandomU128,
    secret_sharing::{Block, FieldVectorizable, SharedValue, StdArray, Vectorizable},
};

pub trait PrimeField: Field + U128Conversions {
    type PrimeInteger: Into<u128>;

    const PRIME: Self::PrimeInteger;

    /// Invert function that returns the multiplicative inverse
    /// the default implementation uses the extended Euclidean algorithm,
    /// follows inversion algorithm in
    /// (with the modification that it works for unsigned integers by keeping track of `sign`):
    /// `https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm`
    ///
    /// The function operates on `u128` rather than field elements since we need divisions
    ///
    /// ## Panics
    /// When `self` is `Zero`
    #[must_use]
    fn invert(&self) -> Self {
        assert_ne!(*self, Self::ZERO);

        let mut t = 0u128;
        let mut newt = 1u128;
        let mut r = Self::PRIME.into();
        let mut newr = self.as_u128();
        let mut sign = 1u128;

        while newr != 0 {
            let quotient = r / newr;
            mem::swap(&mut t, &mut newt);
            mem::swap(&mut r, &mut newr);
            newt += quotient * t;
            newr -= quotient * r;

            // flip sign
            sign = 1 - sign;
        }

        // when sign is negative, output `PRIME-t` otherwise `t`
        // unwrap is safe
        Self::try_from((1 - sign) * t + sign * (Self::PRIME.into() - t)).unwrap()
    }
}

/// Performs multiple field inversions at once for a lower cost
/// Follows the "multiple inverses" algorithm in
/// <https://en.wikipedia.org/wiki/Modular_multiplicative_inverse>
/// ## Panics
/// If any element is 0
#[allow(non_snake_case)]
pub fn batch_invert<P>(field_elements: &mut [P])
where
    P: PrimeField,
{
    let N = field_elements.len();
    let mut prefix_products = field_elements.to_vec();
    for i in 1..N {
        let temp = prefix_products[i] * prefix_products[i - 1];
        prefix_products[i] = temp;
    }
    prefix_products[N - 1] = prefix_products[N - 1].invert();
    for i in (1..N).rev() {
        let inv_i = prefix_products[i] * prefix_products[i - 1];
        let temp = prefix_products[i] * field_elements[i];
        prefix_products[i - 1] = temp;
        field_elements[i] = inv_i;
    }
    field_elements[0] = prefix_products[0];
}

#[derive(thiserror::Error, Debug)]
#[error("Field value {0} provided is greater than prime: {1}")]
pub struct GreaterThanPrimeError<V: Display>(V, u128);

/// Default modulo reduction implementation using the remainder operator.
/// Works for any prime field, but can be inefficient for large primes
/// and if it needs to be done often. Fields operating over Mersenne
/// primes provide an optimized implementation.
macro_rules! rem_modulo_impl {
    ( $field:ident, $op_store:ty ) => {
        impl $field {
            #[must_use]
            fn modulo_prime_base(input: $op_store) -> Self {
                #[allow(clippy::cast_possible_truncation)]
                Self((input % <$op_store>::from(Self::PRIME)) as <Self as SharedValue>::Storage)
            }

            #[must_use]
            fn modulo_prime_u128(input: u128) -> Self
            where
                Self: U128Conversions,
            {
                const PRIME: u128 = $field::PRIME as u128;
                #[allow(clippy::cast_possible_truncation)]
                Self((input % PRIME) as <Self as SharedValue>::Storage)
            }
        }
    };
}

macro_rules! field_impl {
    ( $field:ident, $backend_store:ty, $op_store:ty, $bits:expr, $prime:expr ) => {
        use super::*;

        // check container for multiply is large enough
        const_assert!((<$op_store>::MAX >> $bits) as u128 >= (<$backend_store>::MAX) as u128);

        #[derive(Clone, Copy, PartialEq, Eq)]
        pub struct $field(<Self as SharedValue>::Storage);

        impl SharedValue for $field {
            type Storage = $backend_store;
            const BITS: u32 = $bits;
            const ZERO: Self = $field(0);

            impl_shared_value_common!();
        }

        impl Vectorizable<1> for $field {
            type Array = StdArray<$field, 1>;
        }

        impl FieldVectorizable<1> for $field {
            type ArrayAlias = StdArray<$field, 1>;
        }

        impl Field for $field {
            const NAME: &'static str = stringify!($field);

            const ONE: Self = $field(1);
        }

        impl U128Conversions for $field {
            fn as_u128(&self) -> u128 {
                u128::from(self.0)
            }

            /// An infallible conversion from `u128` to this type.  This can be used to draw
            /// a random value in the field.  This introduces bias into the final value
            /// but for our purposes that bias is small provided that `2^128 >> PRIME`, which
            /// is true provided that `PRIME` is kept to at most 64 bits in value.
            ///
            /// This method is simpler than rejection sampling for these small prime fields.
            fn truncate_from<T: Into<u128>>(v: T) -> Self {
                Self::modulo_prime_u128(v.into())
            }
        }

        impl FromRandomU128 for $field {
            fn from_random_u128(src: u128) -> Self {
                U128Conversions::truncate_from(src)
            }
        }

        impl PrimeField for $field {
            type PrimeInteger = <Self as SharedValue>::Storage;
            const PRIME: Self::PrimeInteger = $prime;
        }

        impl std::ops::Add for $field {
            type Output = Self;

            fn add(self, rhs: Self) -> Self::Output {
                let c = <$op_store>::from;
                debug_assert!(c(Self::PRIME) < (<$op_store>::MAX >> 1));
                #[allow(clippy::cast_possible_truncation)]
                Self::modulo_prime_base(c(self.0) + c(rhs.0))
            }
        }

        impl std::ops::AddAssign for $field {
            #[allow(clippy::assign_op_pattern)]
            fn add_assign(&mut self, rhs: Self) {
                *self = *self + rhs;
            }
        }

        impl std::ops::Neg for $field {
            type Output = Self;

            fn neg(self) -> Self::Output {
                // Invariant uphold by the construction
                // 0 <= self < PRIME
                // therefore it is safe to avoid the modulo operation
                Self(Self::PRIME - self.0)
            }
        }

        impl std::ops::Sub for $field {
            type Output = Self;

            fn sub(self, rhs: Self) -> Self::Output {
                let c = <$op_store>::from;
                debug_assert!(c(Self::PRIME) < (<$op_store>::MAX >> 1));
                // TODO(mt) - constant time?
                Self::modulo_prime_base(c(Self::PRIME) + c(self.0) - c(rhs.0))
            }
        }

        impl std::ops::SubAssign for $field {
            #[allow(clippy::assign_op_pattern)]
            fn sub_assign(&mut self, rhs: Self) {
                *self = *self - rhs;
            }
        }

        impl std::ops::Mul for $field {
            type Output = Self;

            fn mul(self, rhs: Self) -> Self::Output {
                debug_assert!(<$backend_store>::try_from(Self::PRIME).is_ok());
                let c = <$op_store>::from;
                // TODO(mt) - constant time?
                Self::modulo_prime_base(c(self.0) * c(rhs.0))
            }
        }

        impl std::ops::MulAssign for $field {
            #[allow(clippy::assign_op_pattern)]
            fn mul_assign(&mut self, rhs: Self) {
                *self = *self * rhs;
            }
        }

        impl std::iter::Sum for $field {
            fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
                iter.fold(Self::ZERO, |a, b| a + b)
            }
        }

        impl<'a> std::iter::Sum<&'a $field> for $field {
            fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
                iter.fold(Self::ZERO, |a, b| a + *b)
            }
        }

        impl TryFrom<u128> for $field {
            type Error = crate::error::Error;

            fn try_from(v: u128) -> Result<Self, Self::Error> {
                if u128::BITS - v.leading_zeros() <= Self::BITS {
                    Ok(Self::truncate_from(v))
                } else {
                    Err(crate::error::Error::FieldValueTruncation(format!(
                        "Storage size {} is too small to hold the value {}.",
                        Self::BITS,
                        v
                    )))
                }
            }
        }

        impl From<$field> for $backend_store {
            fn from(v: $field) -> Self {
                v.0
            }
        }

        impl rand::distributions::Distribution<$field> for rand::distributions::Standard {
            fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> $field {
                <$field>::truncate_from(rng.gen::<u128>())
            }
        }

        impl std::fmt::Debug for $field {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}_mod{}", self.0, Self::PRIME)
            }
        }

        impl Default for $field {
            fn default() -> Self {
                Self::ZERO
            }
        }

        impl Serializable for $field {
            type Size = <<Self as SharedValue>::Storage as Block>::Size;
            type DeserializationError = GreaterThanPrimeError<$backend_store>;

            fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
                buf.copy_from_slice(&self.0.to_le_bytes());
            }

            fn deserialize(
                buf: &GenericArray<u8, Self::Size>,
            ) -> Result<Self, Self::DeserializationError> {
                let v = <$backend_store>::from_le_bytes((*buf).into());
                if v < Self::PRIME {
                    Ok(Self(v))
                } else {
                    Err(GreaterThanPrimeError(v, Self::PRIME.into()))
                }
            }
        }

        #[cfg(any(test, unit_test))]
        impl $field {
            /// Deserialize a field value, ignoring the fact that it can be greater than PRIME. Therefore, will panic
            /// at runtime.
            ///
            /// This method is available for tests only as a shortcut to `unwrap()`.
            #[allow(unused)]
            pub(crate) fn deserialize_unchecked(
                buf: &GenericArray<u8, <Self as Serializable>::Size>,
            ) -> Self {
                Self::deserialize(buf).unwrap()
            }
        }

        #[cfg(any(test, unit_test))]
        impl std::cmp::PartialEq<u128> for $field {
            fn eq(&self, other: &u128) -> bool {
                self.as_u128() == *other
            }
        }

        #[cfg(any(test, unit_test))]
        impl std::cmp::PartialEq<$field> for u128 {
            fn eq(&self, other: &$field) -> bool {
                *self == other.as_u128()
            }
        }

        #[cfg(all(test, unit_test))]
        mod common_tests {
            use std::ops::Range;

            use generic_array::GenericArray;
            use proptest::{
                prelude::{prop, Arbitrary, Strategy},
                proptest,
            };

            use super::*;
            use crate::{
                ff::Serializable,
                rand::{thread_rng, Rng},
            };

            impl Arbitrary for $field {
                type Parameters = ();
                type Strategy = prop::strategy::Map<Range<u128>, fn(u128) -> Self>;

                fn arbitrary_with(_args: ()) -> Self::Strategy {
                    (0..u128::from(Self::PRIME)).prop_map($field::truncate_from as _)
                }
            }

            #[test]
            fn zero() {
                assert_eq!($field::default(), $field::ZERO);
                let prime = u128::from($field::PRIME);
                assert_eq!(
                    $field::ZERO,
                    $field::try_from(prime).unwrap(),
                    "from takes a modulus",
                );
                assert_eq!($field::ZERO, $field::ZERO + $field::ZERO);
                assert_eq!($field::ZERO, $field::ZERO - $field::ZERO);
                assert_eq!(
                    $field::try_from(prime - 1).unwrap(),
                    $field::ZERO - $field::ONE
                );
                assert_eq!($field::ZERO, $field::ZERO * $field::ONE);
            }

            #[test]
            fn batch_invert_test() {
                let mut rng = thread_rng();
                let mut elements = (0..100)
                    .into_iter()
                    .map(|_i| $field::truncate_from(rng.gen::<u128>()))
                    .filter(|x| *x != $field::ZERO)
                    .collect::<Vec<$field>>();
                let ground_truth = elements.iter().map(|x| x.invert()).collect::<Vec<$field>>();
                batch_invert(&mut elements);
                assert_eq!(ground_truth, elements);
            }

            proptest! {

                #[test]
                #[allow(clippy::ignored_unit_patterns)]
                fn serde(v in 0..$field::PRIME) {
                    let field_v = $field(v);
                    let mut buf = GenericArray::default();
                    field_v.serialize(&mut buf);

                    assert_eq!(field_v, $field::deserialize_unchecked(&buf));
                }

                #[test]
                #[allow(clippy::ignored_unit_patterns)]
                fn deserialize_fail_if_greater_than_prime(v in $field::PRIME..) {
                    let mut buf = GenericArray::default();
                    buf.copy_from_slice(&v.to_le_bytes());
                    let err = $field::deserialize(&buf).unwrap_err();
                    assert!(matches!(err, GreaterThanPrimeError(..)))
                }

                #[test]
                fn invert(element: $field) {
                    if element != $field::ZERO
                    {
                        assert_eq!($field::ONE,element * element.invert() );
                    }
                }
            }
        }
    };
}

#[cfg(any(test, feature = "weak-field"))]
mod fp31 {
    field_impl! { Fp31, u8, u16, 8, 31 }
    rem_modulo_impl! { Fp31, u16 }

    #[cfg(all(test, unit_test))]
    mod specialized_tests {
        use super::*;

        #[test]
        fn fp31() {
            let x = Fp31(24);
            let y = Fp31(23);

            assert_eq!(Fp31(16), x + y);
            assert_eq!(Fp31(25), x * y);
            assert_eq!(Fp31(1), x - y);

            let mut x = Fp31(1);
            x += Fp31(2);
            assert_eq!(Fp31(3), x);
        }
    }
}

mod fp32bit {
    field_impl! { Fp32BitPrime, u32, u64, 32, 4_294_967_291 }
    rem_modulo_impl! { Fp32BitPrime, u64 }

    impl Vectorizable<32> for Fp32BitPrime {
        type Array = StdArray<Fp32BitPrime, 32>;
    }

    impl FieldVectorizable<32> for Fp32BitPrime {
        type ArrayAlias = StdArray<Fp32BitPrime, 32>;
    }

    #[cfg(all(test, unit_test))]
    mod specialized_tests {
        use super::*;

        #[test]
        fn thirty_two_bit_prime() {
            let x = Fp32BitPrime::truncate_from(4_294_967_290_u32); // PRIME - 1
            let y = Fp32BitPrime::truncate_from(4_294_967_289_u32); // PRIME - 2

            assert_eq!(x - y, Fp32BitPrime::ONE);
            assert_eq!(y - x, Fp32BitPrime::truncate_from(Fp32BitPrime::PRIME - 1));
            assert_eq!(y + x, Fp32BitPrime::truncate_from(Fp32BitPrime::PRIME - 3));

            assert_eq!(x * y, Fp32BitPrime::truncate_from(2_u32),);

            let x = Fp32BitPrime::truncate_from(3_192_725_551_u32);
            let y = Fp32BitPrime::truncate_from(1_471_265_983_u32);

            assert_eq!(x - y, Fp32BitPrime::truncate_from(1_721_459_568_u32));
            assert_eq!(y - x, Fp32BitPrime::truncate_from(2_573_507_723_u32));
            assert_eq!(x + y, Fp32BitPrime::truncate_from(369_024_243_u32));

            assert_eq!(x * y, Fp32BitPrime::truncate_from(513_684_208_u32),);
        }

        #[test]
        fn thirty_two_bit_additive_wrapping() {
            let x = Fp32BitPrime::truncate_from(u32::MAX - 20);
            let y = Fp32BitPrime::truncate_from(20_u32);
            assert_eq!(x + y, Fp32BitPrime::truncate_from(4_u32));

            let x = Fp32BitPrime::truncate_from(u32::MAX - 20);
            let y = Fp32BitPrime::truncate_from(21_u32);
            assert_eq!(x + y, Fp32BitPrime::truncate_from(5_u32));

            let x = Fp32BitPrime::truncate_from(u32::MAX - 20);
            let y = Fp32BitPrime::truncate_from(22_u32);
            assert_eq!(x + y, Fp32BitPrime::truncate_from(6_u32));

            let x = Fp32BitPrime::truncate_from(4_294_967_290_u32); // PRIME - 1
            let y = Fp32BitPrime::truncate_from(4_294_967_290_u32); // PRIME - 1
            assert_eq!(x + y, Fp32BitPrime::truncate_from(4_294_967_289_u32));
        }
    }
}

mod fp61bit {
    field_impl! { Fp61BitPrime, u64, u128, 61, 2_305_843_009_213_693_951 }

    impl Fp61BitPrime {
        #[must_use]
        pub const fn const_truncate(input: u64) -> Self {
            Self(input % Self::PRIME)
        }

        /// `from_bit` is more efficient than `truncate_from` since it does not use a mod operation.
        /// However, it only allows conversions from `bool`.
        #[must_use]
        pub fn from_bit(input: bool) -> Self {
            Self(input.into())
        }

        #[must_use]
        fn modulo_prime_base(val: u128) -> Self {
            Self::modulo_prime_u128(val)
        }

        /// Implements optimized modulus division operation for Mersenne fields.
        /// Implementation taken from [`bit_twiddling`].
        ///
        /// [`bit_twiddling`]: https://graphics.stanford.edu/~seander/bithacks.html#ModulusDivision
        #[must_use]
        #[allow(clippy::cast_possible_truncation)]
        fn modulo_prime_u128(val: u128) -> Self
        where
            Self: U128Conversions,
        {
            const PRIME: u128 = Fp61BitPrime::PRIME as u128;
            debug_assert_eq!(0, PRIME & (PRIME + 1), "{PRIME} is not a Mersenne prime");

            let val = (val & PRIME) + (val >> Self::BITS);
            // another round if val ended up being greater than PRIME
            let val = (val & PRIME) + (val >> Self::BITS);
            if val == PRIME {
                Self::ZERO
            } else {
                Self(val as <Self as SharedValue>::Storage)
            }
        }
    }

    #[cfg(all(test, unit_test))]
    mod specialized_tests {
        use proptest::proptest;

        use super::*;

        // copied from 32 bit prime field, adjusted wrap arounds, computed using wolframalpha.com
        #[test]
        fn sixty_one_bit_prime() {
            let x = Fp61BitPrime::truncate_from(2_305_843_009_213_693_950_u64); // PRIME - 1
            let y = Fp61BitPrime::truncate_from(2_305_843_009_213_693_949_u64); // PRIME - 2

            assert_eq!(x - y, Fp61BitPrime::ONE);
            assert_eq!(y - x, Fp61BitPrime::truncate_from(Fp61BitPrime::PRIME - 1));
            assert_eq!(y + x, Fp61BitPrime::truncate_from(Fp61BitPrime::PRIME - 3));

            assert_eq!(x * y, Fp61BitPrime::truncate_from(2_u32));

            let x = Fp61BitPrime::truncate_from(3_192_725_551_u32);
            let y = Fp61BitPrime::truncate_from(1_471_265_983_u32);

            assert_eq!(x - y, Fp61BitPrime::truncate_from(1_721_459_568_u32));
            assert_eq!(
                y - x,
                Fp61BitPrime::truncate_from(2_305_843_007_492_234_383_u64)
            );
            assert_eq!(x + y, Fp61BitPrime::truncate_from(4_663_991_534_u64));

            assert_eq!(
                x * y,
                Fp61BitPrime::truncate_from(85_662_477_813_843_731_u64),
            );
        }

        #[test]
        fn sixty_one_bit_additive_wrapping() {
            let x = Fp61BitPrime::truncate_from((u64::MAX >> 3) - 20);
            let y = Fp61BitPrime::truncate_from(20_u32);
            assert_eq!(x + y, Fp61BitPrime::truncate_from(0_u32));

            let x = Fp61BitPrime::truncate_from((u64::MAX >> 3) - 20);
            let y = Fp61BitPrime::truncate_from(21_u32);
            assert_eq!(x + y, Fp61BitPrime::truncate_from(1_u32));

            let x = Fp61BitPrime::truncate_from((u64::MAX >> 3) - 20);
            let y = Fp61BitPrime::truncate_from(22_u32);
            assert_eq!(x + y, Fp61BitPrime::truncate_from(2_u32));

            let x = Fp61BitPrime::truncate_from((u64::MAX >> 3) - 1); // PRIME - 1
            let y = Fp61BitPrime::truncate_from((u64::MAX >> 3) - 1); // PRIME - 1
            assert_eq!(x + y, Fp61BitPrime::truncate_from((u64::MAX >> 3) - 2));
        }

        proptest! {
            #[test]
            fn add(a: Fp61BitPrime, b: Fp61BitPrime) {
                let c = a + b;
                assert!(c.0 < Fp61BitPrime::PRIME);
                assert_eq!(c.0, (a.0 + b.0) % Fp61BitPrime::PRIME);
            }

            #[test]
            fn sub(a: Fp61BitPrime, b: Fp61BitPrime) {
                let c = a - b;
                assert!(c.0 < Fp61BitPrime::PRIME);
                assert_eq!(c.0, (Fp61BitPrime::PRIME + a.0 - b.0) % Fp61BitPrime::PRIME);
            }

            #[test]
            fn mul(a: Fp61BitPrime, b: Fp61BitPrime) {
                let c = a * b;
                assert!(c.0 < Fp61BitPrime::PRIME);
                assert_eq!(c.0, u64::try_from((u128::from(a.0) * u128::from(b.0)) % u128::from(Fp61BitPrime::PRIME)).unwrap());
            }

            #[test]
            fn neg(a: Fp61BitPrime) {
                let c = -a;
                assert!(c.0 < Fp61BitPrime::PRIME);
                assert_eq!(0, c + a);
                assert_eq!(Fp61BitPrime::PRIME, c.0 + a.0);
            }

            #[test]
            fn truncate(a: u64) {
                assert_eq!(Fp61BitPrime::truncate_from(a).0, a % Fp61BitPrime::PRIME);
            }
        }
    }
}

#[cfg(any(test, feature = "weak-field"))]
pub use fp31::Fp31;
pub use fp32bit::Fp32BitPrime;
pub use fp61bit::Fp61BitPrime;
