use bitvec::{
    prelude::{bitarr, BitArr, Lsb0},
    slice::Iter,
};
use generic_array::GenericArray;
use typenum::{U14, U2, U32, U8};

use crate::{
    ff::{boolean::Boolean, ArrayAccess, Field, Serializable},
    protocol::prss::{FromRandom, FromRandomU128},
    secret_sharing::{Block, SharedValue},
};

/// The implementation below cannot be constrained without breaking Rust's
/// macro processor.  This noop ensures that the instance of `GenericArray` used
/// is `Copy`.  It should be - it's the same size as the `BitArray` instance.
fn assert_copy<C: Copy>(c: C) -> C {
    c
}

/// this might clash with Galois field, i.e. `galois_field.rs`
/// so only use it for byte sizes for which Block has not been defined yet
macro_rules! store_impl {
    ($arraylength:ty, $bits:expr) => {
        impl Block for BitArr!(for $bits, in u8, Lsb0) {
            type Size = $arraylength;
        }
    };
}

/// iterator for Boolean arrays
pub struct BAIterator<'a> {
    iterator: std::iter::Take<Iter<'a, u8, Lsb0>>,
}

///impl Iterator for all Boolean arrays
impl<'a> Iterator for BAIterator<'a> {
    type Item = Boolean;

    fn next(&mut self) -> Option<Self::Item> {
        self.iterator.next().map(|v| Boolean::from(*v))
    }
}

/// A value of ONE has a one in the first element of the bit array, followed by `$bits-1` zeros.
/// This macro uses a bit of recursive repetition to produce those zeros.
///
/// The longest call is 8 bits, which involves `2(n+1)` macro expansions in addition to `bitarr!`.
macro_rules! bitarr_one {

    // The binary value of `$bits-1` is expanded in MSB order for each of the values we care about.
    // e.g., 20 =(-1)=> 19 =(binary)=> 0b10011 =(expand)=> 1 0 0 1 1

    (2) => { bitarr_one!(1) };
    (3) => { bitarr_one!(1 0) };
    (4) => { bitarr_one!(1 1) };
    (5) => { bitarr_one!(1 0 0) };
    (6) => { bitarr_one!(1 0 1) };
    (7) => { bitarr_one!(1 1 0) };
    (8) => { bitarr_one!(1 1 1) };
    (20) => { bitarr_one!(1 0 0 1 1) };
    (32) => { bitarr_one!(1 1 1 1 1) };
    (64) => { bitarr_one!(1 1 1 1 1 1) };
    (112) => { bitarr_one!(1 1 0 1 1 1 1) };
    (256) => { bitarr_one!(1 1 1 1 1 1 1 1) };

    // Incrementally convert 1 or 0 into `[0,]` or `[]` as needed for the recursion step.
    // This also reverses the bit order so that the MSB comes last, as needed for recursion.

    // This passes a value back once the conversion is done.
    ($([$($x:tt)*])*) => { bitarr_one!(@r $([$($x)*])*) };
    // This converts one 1 into `[0,]`.
    ($([$($x:tt)*])* 1 $($y:tt)*) => { bitarr_one!([0,] $([$($x)*])* $($y)*) };
    // This converts one 0 into `[]`.
    ($([$($x:tt)*])* 0 $($y:tt)*) => { bitarr_one!([] $([$($x)*])* $($y)*) };

    // Recursion step.

    // This is where recursion ends with a `BitArray`.
    (@r [$($x:tt)*]) => { bitarr![const u8, Lsb0; 1, $($x)*] };
    // This is the recursion workhorse.  It takes a list of lists.  The outer lists are bracketed.
    // The inner lists contain any form that can be repeated and concatenated, which probably
    // means comma-separated values with a trailing comma.
    // The first value is repeated once.
    // The second value is repeated twice and merged into the first value.
    // The third and subsequent values are repeated twice and shifted along one place.
    // One-valued bits are represented as `[0,]`, zero-valued bits as `[]`.
    (@r [$($x:tt)*] [$($y:tt)*] $([$($z:tt)*])*) => { bitarr_one!(@r [$($x)* $($y)* $($y)*] $([$($z)* $($z)*])*) };
}

// Macro for boolean arrays <= 128 bits.
macro_rules! boolean_array_impl_small {
    ($modname:ident, $name:ident, $bits:tt) => {
        boolean_array_impl!($modname, $name, $bits);

        // TODO(812): remove this impl; BAs are not field elements.
        impl Field for $name {
            const ONE: Self = Self(bitarr_one!($bits));

            fn as_u128(&self) -> u128 {
                (*self).into()
            }

            fn truncate_from<T: Into<u128>>(v: T) -> Self {
                let v = v.into();
                let mut val = <Self as SharedValue>::ZERO;
                for i in 0..std::cmp::min(128, $bits) {
                    val.set(i, Boolean::from((v >> i & 1) == 1));
                }

                val
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

        impl From<$name> for u128 {
            /// Infallible conversion from this data type to `u128`.
            fn from(v: $name) -> u128 {
                debug_assert!(<$name>::BITS <= 128);
                v.0.iter()
                    .by_refs()
                    .enumerate()
                    .fold(0_u128, |acc, (i, b)| acc + ((*b as u128) << i))
            }
        }

        impl rand::distributions::Distribution<$name> for rand::distributions::Standard {
            fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> $name {
                <$name>::from_random_u128(rng.gen::<u128>())
            }
        }

        impl FromRandomU128 for $name {
            fn from_random_u128(src: u128) -> Self {
                Field::truncate_from(src)
            }
        }
    };
}

//macro for implementing Boolean array, only works for a byte size for which Block is defined
macro_rules! boolean_array_impl {
    ($modname:ident, $name:ident, $bits:tt) => {
        #[allow(clippy::suspicious_arithmetic_impl)]
        #[allow(clippy::suspicious_op_assign_impl)]
        mod $modname {
            use super::*;
            use crate::{
                ff::{boolean::Boolean, ArrayAccess, Expand, Serializable},
                secret_sharing::{
                    replicated::semi_honest::{ASIterator, AdditiveShare},
                    SharedValue,
                },
            };

    type Store = BitArr!(for $bits, in u8, Lsb0);

            /// A Boolean array with $bits bits.
            #[derive(Clone, Copy, PartialEq, Eq, Debug)]
            pub struct $name(pub Store);

            impl ArrayAccess for $name {
                type Output = Boolean;
                type Iter<'a> = BAIterator<'a>;

                fn get(&self, index: usize) -> Option<Self::Output> {
                    if index < usize::try_from(<$name>::BITS).unwrap() {
                        Some(self.0[index].into())
                    } else {
                        None
                    }
                }

                fn set(&mut self, index: usize, e: Self::Output) {
                    debug_assert!(index < usize::try_from(<$name>::BITS).unwrap());
                    self.0.set(index, bool::from(e));
                }

                fn iter(&self) -> Self::Iter<'_> {
                    BAIterator {
                        iterator: self.0.iter().take(<$name>::BITS as usize),
                    }
                }
            }

            impl SharedValue for $name {
                type Storage = Store;
                const BITS: u32 = $bits;
                const ZERO: Self = Self(<Store>::ZERO);
            }

            impl Serializable for $name {
                type Size = <Store as Block>::Size;

                fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
                    buf.copy_from_slice(self.0.as_raw_slice());
                }

                fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
                    Self(<Store>::new(assert_copy(*buf).into()))
                }
            }

            impl std::ops::Add for $name {
                type Output = Self;
                fn add(self, rhs: Self) -> Self::Output {
                    Self(self.0 ^ rhs.0)
                }
            }

            impl std::ops::Add<&$name> for $name {
                type Output = $name;
                fn add(self, rhs: &$name) -> Self::Output {
                    $name(self.0 ^ rhs.0)
                }
            }

            impl std::ops::Add<$name> for &$name {
                type Output = $name;
                fn add(self, rhs: $name) -> Self::Output {
                    $name(self.0 ^ rhs.0)
                }
            }

            impl<'a, 'b> std::ops::Add<&'b $name> for &'a $name {
                type Output = $name;
                fn add(self, rhs: &'b $name) -> Self::Output {
                    $name(self.0 ^ rhs.0)
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

            impl std::ops::Neg for $name {
                type Output = Self;
                fn neg(self) -> Self::Output {
                    Self(self.0)
                }
            }

            impl std::ops::Mul for $name {
                type Output = Self;
                fn mul(self, rhs: Self) -> Self::Output {
                    Self(self.0 & rhs.0)
                }
            }

            impl std::ops::MulAssign for $name {
                fn mul_assign(&mut self, rhs: Self) {
                    *self = *self * rhs;
                }
            }

            impl From<$name> for Store {
                fn from(v: $name) -> Self {
                    v.0
                }
            }

            impl Expand for $name {
                type Input = Boolean;

                fn expand(v: &Boolean) -> Self {
                    let mut result = <$name>::ZERO;
                    for i in 0..usize::try_from(<$name>::BITS).unwrap() {
                        result.set(i, *v);
                    }
                    result
                }
            }

            impl<'a> IntoIterator for &'a $name {
                type Item = Boolean;
                type IntoIter = BAIterator<'a>;

                fn into_iter(self) -> Self::IntoIter {
                    self.iter()
                }
            }

            impl<'a> IntoIterator for &'a AdditiveShare<$name> {
                type Item = AdditiveShare<Boolean>;
                type IntoIter = ASIterator<BAIterator<'a>>;

                fn into_iter(self) -> Self::IntoIter {
                    self.iter()
                }
            }

            impl std::ops::Not for $name {
                type Output = Self;

                fn not(self) -> Self::Output {
                    Self(self.0.not())
                }
            }

            #[cfg(all(test, unit_test))]
            mod tests {
                use rand::{thread_rng, Rng};

                use super::*;

                // Only small BAs expose this via `Field`.
                const ONE: $name = $name(bitarr_one!($bits));

                #[test]
                fn set_boolean_array() {
                    let mut rng = thread_rng();
                    let i = rng.gen::<usize>() % usize::try_from(<$name>::BITS).unwrap();
                    let a = rng.gen::<Boolean>();
                    let mut ba = rng.gen::<$name>();
                    ba.set(i, a);
                    assert_eq!(ba.get(i), Some(a));
                }

                #[test]
                fn iterate_boolean_array() {
                    let bits = ONE;
                    let iter = bits.into_iter();
                    for (i, j) in iter.enumerate() {
                        if i == 0 {
                            assert_eq!(j, Boolean::ONE);
                        } else {
                            assert_eq!(j, Boolean::ZERO);
                        }
                    }
                }

                #[test]
                fn iterate_secret_shared_boolean_array() {
                    use crate::secret_sharing::replicated::ReplicatedSecretSharing;
                    let bits = AdditiveShare::new(ONE, ONE);
                    let iter = bits.into_iter();
                    for (i, j) in iter.enumerate() {
                        if i == 0 {
                            assert_eq!(j, AdditiveShare::new(Boolean::ONE, Boolean::ONE));
                        } else {
                            assert_eq!(j, AdditiveShare::<Boolean>::ZERO);
                        }
                    }
                }
            }
        }

        pub use $modname::$name;
    };
}

//impl store for U8
store_impl!(U8, 64);

//impl store for U14
store_impl!(U14, 112);

//impl store for U32
store_impl!(U32, 256);

//impl BA3
boolean_array_impl_small!(boolean_array_3, BA3, 3);
boolean_array_impl_small!(boolean_array_4, BA4, 4);
boolean_array_impl_small!(boolean_array_5, BA5, 5);
boolean_array_impl_small!(boolean_array_6, BA6, 6);
boolean_array_impl_small!(boolean_array_7, BA7, 7);
boolean_array_impl_small!(boolean_array_8, BA8, 8);
boolean_array_impl_small!(boolean_array_20, BA20, 20);
boolean_array_impl_small!(boolean_array_32, BA32, 32);
boolean_array_impl_small!(boolean_array_64, BA64, 64);
boolean_array_impl_small!(boolean_array_112, BA112, 112);
boolean_array_impl!(boolean_array_256, BA256, 256);

// used to convert into Fp25519
impl From<(u128, u128)> for BA256 {
    fn from(value: (u128, u128)) -> Self {
        let iter = value
            .0
            .to_le_bytes()
            .into_iter()
            .chain(value.1.to_le_bytes());
        let arr = GenericArray::<u8, U32>::try_from_iter(iter).unwrap();
        BA256::deserialize(&arr)
    }
}

impl FromRandom for BA256 {
    type SourceLength = U2;
    fn from_random(src: GenericArray<u128, U2>) -> Self {
        (src[0], src[1]).into()
    }
}

impl rand::distributions::Distribution<BA256> for rand::distributions::Standard {
    fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> BA256 {
        (rng.gen(), rng.gen()).into()
    }
}
