use std::iter::Once;

use bitvec::prelude::BitSlice;
use generic_array::GenericArray;
use typenum::U1;

use crate::{
    ff::{ArrayAccess, Field, PrimeField, Serializable, U128Conversions},
    impl_shared_value_common,
    protocol::{
        context::{dzkp_field::DZKPCompatibleField, dzkp_validator::SegmentEntry},
        prss::FromRandomU128,
    },
    secret_sharing::{Block, FieldVectorizable, SharedValue, StdArray, Vectorizable},
};
impl Block for bool {
    type Size = U1;
}

///implements shared value framework for bool
#[derive(Clone, Copy, Default, PartialEq, Debug, Eq)]
pub struct Boolean(bool);

impl Boolean {
    pub const TRUE: Boolean = Self(true);
    pub const FALSE: Boolean = Self(false);

    #[must_use]
    pub fn as_u128(&self) -> u128 {
        u128::from(bool::from(*self))
    }
}

impl ArrayAccess for Boolean {
    type Output = Boolean;
    type Iter<'a> = Once<Boolean>;

    fn get(&self, index: usize) -> Option<Self::Output> {
        if index < 1 {
            Some(*self)
        } else {
            None
        }
    }

    fn set(&mut self, index: usize, e: Self::Output) {
        debug_assert!(index < 1);
        *self = e;
    }

    fn iter(&self) -> Self::Iter<'_> {
        std::iter::once(*self)
    }
}

impl PrimeField for Boolean {
    type PrimeInteger = u8;
    const PRIME: Self::PrimeInteger = 2;
}

impl SharedValue for Boolean {
    type Storage = bool;
    const BITS: u32 = 1;
    const ZERO: Self = Self(false);

    impl_shared_value_common!();
}

impl Vectorizable<1> for Boolean {
    type Array = StdArray<Boolean, 1>;
}

impl FieldVectorizable<1> for Boolean {
    type ArrayAlias = StdArray<Boolean, 1>;
}

///conversion to Scalar struct of `curve25519_dalek`
impl From<Boolean> for bool {
    fn from(s: Boolean) -> Self {
        s.0
    }
}

#[derive(thiserror::Error, Debug)]
#[error("{0} is not a valid boolean value, only 0 and 1 are accepted.")]
pub struct ParseBooleanError(u8);

impl Serializable for Boolean {
    type Size = <<Boolean as SharedValue>::Storage as Block>::Size;
    type DeserializationError = ParseBooleanError;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        buf[0] = u8::from(self.0);
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserializationError> {
        if buf[0] > 1 {
            return Err(ParseBooleanError(buf[0]));
        }
        Ok(Boolean(buf[0] != 0))
    }
}

///generate random bool
impl rand::distributions::Distribution<Boolean> for rand::distributions::Standard {
    fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> Boolean {
        Boolean(rng.gen::<bool>())
    }
}

impl std::ops::Add for Boolean {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl std::ops::AddAssign for Boolean {
    #[allow(clippy::assign_op_pattern)]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl std::ops::Neg for Boolean {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

impl std::ops::Sub for Boolean {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}

impl std::ops::SubAssign for Boolean {
    #[allow(clippy::assign_op_pattern)]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl std::ops::Mul for Boolean {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl std::ops::MulAssign for Boolean {
    #[allow(clippy::assign_op_pattern)]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl std::ops::Not for Boolean {
    type Output = Self;

    fn not(self) -> Self::Output {
        Boolean(!self.0)
    }
}

impl From<bool> for Boolean {
    fn from(s: bool) -> Self {
        Boolean(s)
    }
}

impl Field for Boolean {
    const NAME: &'static str = "Boolean";

    const ONE: Boolean = Boolean(true);
}

impl U128Conversions for Boolean {
    fn as_u128(&self) -> u128 {
        Boolean::as_u128(self)
    }

    fn truncate_from<T: Into<u128>>(v: T) -> Self {
        Boolean((v.into() % 2u128) != 0)
    }
}

///implement `TryFrom` since required by Field
impl TryFrom<u128> for Boolean {
    type Error = crate::error::Error;

    fn try_from(v: u128) -> Result<Self, Self::Error> {
        if v < 2u128 {
            Ok(Boolean(v != 0u128))
        } else {
            Err(crate::error::Error::FieldValueTruncation(format!(
                "Boolean size {} is too small to hold the value {}.",
                Self::BITS,
                v
            )))
        }
    }
}

impl FromRandomU128 for Boolean {
    fn from_random_u128(src: u128) -> Self {
        Self::truncate_from(src)
    }
}

impl DZKPCompatibleField for Boolean {
    fn as_segment_entry(array: &<Self as Vectorizable<1>>::Array) -> SegmentEntry<'_> {
        if bool::from(Boolean::from_array(array)) {
            SegmentEntry::from_bitslice(BitSlice::from_element(&1u8).get(0..1).unwrap())
        } else {
            SegmentEntry::from_bitslice(BitSlice::from_element(&0u8).get(0..1).unwrap())
        }
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use generic_array::GenericArray;
    use proptest::prelude::{prop, Arbitrary, Strategy};
    use rand::{thread_rng, Rng};
    use typenum::U1;

    use crate::{
        ff::{boolean::Boolean, ArrayAccess, Field, Serializable},
        protocol::context::dzkp_field::DZKPCompatibleField,
        secret_sharing::{SharedValue, Vectorizable},
    };

    impl Arbitrary for Boolean {
        type Parameters = <bool as Arbitrary>::Parameters;
        type Strategy = prop::strategy::Map<<bool as Arbitrary>::Strategy, fn(bool) -> Self>;

        fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
            <bool>::arbitrary_with(args).prop_map(Boolean)
        }
    }

    ///test serialize and deserialize
    #[test]
    fn serde_boolean() {
        let mut rng = thread_rng();
        let input = rng.gen::<Boolean>();
        let mut a: GenericArray<u8, U1> = [0u8; 1].into();
        input.serialize(&mut a);
        let output = Boolean::deserialize(&a).unwrap();
        assert_eq!(input, output);
    }

    ///test simple arithmetics
    #[test]
    fn simple_arithmetics_boolean() {
        let mut rng = thread_rng();
        let a = rng.gen::<Boolean>();
        let b = rng.gen::<Boolean>();
        let c = rng.gen::<Boolean>();
        let d = rng.gen::<Boolean>();
        assert_eq!((a + b) * (c + d), a * c + a * d + b * c + b * d);
    }

    ///test not
    #[test]
    fn not_boolean() {
        let mut rng = thread_rng();
        let a = rng.gen::<Boolean>();
        assert_ne!(a, !a);
    }

    #[test]
    fn boolean_bitslice() {
        let one = Boolean::ONE;
        let zero = Boolean::ZERO;

        // convert into vectorizable
        let one_vec: <Boolean as Vectorizable<1>>::Array = one.into_array();
        let zero_vec: <Boolean as Vectorizable<1>>::Array = zero.into_array();

        // generate slices
        let slice_one = <Boolean as DZKPCompatibleField<1>>::as_segment_entry(&one_vec);
        let slice_zero = <Boolean as DZKPCompatibleField<1>>::as_segment_entry(&zero_vec);

        // check length
        assert_eq!(slice_one.len(), 1usize);
        assert_eq!(slice_zero.len(), 1usize);

        // check content
        assert_ne!(*slice_one.as_bitslice(), *slice_zero.as_bitslice());
        assert!(slice_one.as_bitslice().first().unwrap());
        assert!(!slice_zero.as_bitslice().first().unwrap());

        // there is nothing more
        assert!(slice_one.as_bitslice().get(1).is_none());
        assert!(slice_zero.as_bitslice().get(1).is_none());
    }

    /// test `ArrayAccess` for Boolean
    #[test]
    fn test_array_access() {
        let mut b = Boolean::from(true);

        // Test get()
        assert_eq!(b.get(0), Some(Boolean::from(true)));
        assert_eq!(b.get(1), None);

        // Test set()
        b.set(0, Boolean::from(false));
        assert_eq!(b.get(0), Some(Boolean::from(false)));

        // Test iter()
        assert_eq!(vec![Boolean::from(false)], b.iter().collect::<Vec<_>>());
    }
}
