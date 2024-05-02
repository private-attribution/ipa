use bitvec::{macros::internal::funty::Fundamental, slice::BitSlice};
use generic_array::GenericArray;

use crate::{
    ff::{Field, PrimeField, Serializable, U128Conversions},
    impl_shared_value_common,
    protocol::{
        context::{dzkp_field::DZKPCompatibleField, dzkp_validator::SegmentEntry},
        prss::FromRandomU128,
    },
    secret_sharing::{Block, FieldVectorizable, SharedValue, StdArray, Vectorizable},
};

///implements shared value framework for bool
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct Boolean(u8);

impl Boolean {
    pub const TRUE: Boolean = Self(1u8);
    pub const FALSE: Boolean = Self(0u8);

    #[must_use]
    pub fn as_u128(&self) -> u128 {
        u128::from(bool::from(*self))
    }
}

impl PrimeField for Boolean {
    type PrimeInteger = u8;
    const PRIME: Self::PrimeInteger = 2;
}

impl SharedValue for Boolean {
    type Storage = u8;
    const BITS: u32 = 1;
    const ZERO: Self = Self(0u8);

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
        s.0 != 0
    }
}

impl From<Boolean> for u8 {
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
        buf[0] = self.0;
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserializationError> {
        if buf[0] > 1 {
            return Err(ParseBooleanError(buf[0]));
        }
        Ok(Boolean(buf[0]))
    }
}

///generate random bool
impl rand::distributions::Distribution<Boolean> for rand::distributions::Standard {
    fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> Boolean {
        Boolean::from(rng.gen::<bool>())
    }
}

impl std::ops::Add for Boolean {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self((self.0 + rhs.0) % Self::PRIME)
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
        self + Self::ONE
    }
}

impl From<bool> for Boolean {
    fn from(s: bool) -> Self {
        Boolean(u8::from(s))
    }
}

impl Field for Boolean {
    const NAME: &'static str = "Boolean";

    const ONE: Boolean = Boolean(1u8);
}

impl U128Conversions for Boolean {
    fn as_u128(&self) -> u128 {
        Boolean::as_u128(self)
    }

    fn truncate_from<T: Into<u128>>(v: T) -> Self {
        Boolean(u8::from(v.into() % Self::PRIME.as_u128() != 0))
    }
}

///implement `TryFrom` since required by Field
impl TryFrom<u128> for Boolean {
    type Error = crate::error::Error;

    fn try_from(v: u128) -> Result<Self, Self::Error> {
        if v < 2u128 {
            Ok(Boolean(u8::from(v != 0u128)))
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

impl AsRef<u8> for Boolean {
    fn as_ref(&self) -> &u8 {
        &self.0
    }
}

impl DZKPCompatibleField for Boolean {
    fn as_segment_entry(array: &<Self as Vectorizable<1>>::Array) -> SegmentEntry<'_> {
        SegmentEntry::from_bitslice(BitSlice::from_element(array.first().as_ref()))
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use generic_array::GenericArray;
    use proptest::prelude::{prop, Arbitrary, Strategy};
    use rand::{thread_rng, Rng};
    use typenum::U1;

    use crate::ff::{boolean::Boolean, Serializable};

    impl Arbitrary for Boolean {
        type Parameters = <bool as Arbitrary>::Parameters;
        type Strategy = prop::strategy::Map<<bool as Arbitrary>::Strategy, fn(bool) -> Self>;

        fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
            <bool>::arbitrary_with(args).prop_map(Boolean::from)
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
}
