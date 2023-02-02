use crate::bits::Serializable;
use crate::helpers::Role;
use crate::secret_sharing::{Boolean as BooleanSecretSharing, BooleanShare, SecretSharing};
use aes::cipher::generic_array::GenericArray;

use generic_array::ArrayLength;
use typenum::Unsigned;

use std::ops::Add;
use std::{
    fmt::{Debug, Formatter},
    ops::{BitXor, BitXorAssign},
};

#[derive(Clone, PartialEq, Eq)]
pub struct XorShare<V: BooleanShare>(V, V);

impl<V: BooleanShare> SecretSharing<V> for XorShare<V> {
    const ZERO: Self = XorShare::ZERO;
}

impl<V: BooleanShare> BooleanSecretSharing<V> for XorShare<V> {}

impl<V: BooleanShare + Debug> Debug for XorShare<V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "({:?}, {:?})", self.0, self.1)
    }
}

impl<V: BooleanShare> Default for XorShare<V> {
    fn default() -> Self {
        XorShare::new(V::ZERO, V::ZERO)
    }
}

impl<V: BooleanShare> XorShare<V> {
    #[must_use]
    pub fn new(a: V, b: V) -> Self {
        Self(a, b)
    }

    pub fn as_tuple(&self) -> (V, V) {
        (self.0, self.1)
    }

    pub fn left(&self) -> V {
        self.0
    }

    pub fn right(&self) -> V {
        self.1
    }

    /// Returns share of a scalar value.
    pub fn from_scalar(helper_role: Role, a: V) -> Self {
        match helper_role {
            Role::H1 => Self::new(a, V::ZERO),
            Role::H2 => Self::new(V::ZERO, V::ZERO),
            Role::H3 => Self::new(V::ZERO, a),
        }
    }

    /// Replicated secret share where both left and right values are `V::ZERO`
    pub const ZERO: XorShare<V> = Self(V::ZERO, V::ZERO);
}

impl<V: BooleanShare> BitXor<Self> for &XorShare<V> {
    type Output = XorShare<V>;

    fn bitxor(self, rhs: Self) -> Self::Output {
        XorShare(self.0 ^ rhs.0, self.1 ^ rhs.1)
    }
}

impl<V: BooleanShare> BitXor<&Self> for XorShare<V> {
    type Output = Self;

    fn bitxor(mut self, rhs: &Self) -> Self::Output {
        self ^= rhs;
        self
    }
}

impl<V: BooleanShare> BitXorAssign<&Self> for XorShare<V> {
    fn bitxor_assign(&mut self, rhs: &Self) {
        self.0 ^= rhs.0;
        self.1 ^= rhs.1;
    }
}

impl<V: BooleanShare> Serializable for XorShare<V>
where
    V::Size: Add<V::Size>,
    <V::Size as Add<V::Size>>::Output: ArrayLength<u8>,
{
    /// This constraint means that the serialized size must be `V::SIZE` + `V::SIZE`, i.e. `2 * V::SIZE`
    type Size = <V::Size as Add<V::Size>>::Output;

    fn serialize(self, buf: &mut GenericArray<u8, Self::Size>) {
        let (left, right) = buf.split_at_mut(V::Size::USIZE);
        self.left().serialize(GenericArray::from_mut_slice(left));
        self.right().serialize(GenericArray::from_mut_slice(right));
    }

    fn deserialize(buf: GenericArray<u8, Self::Size>) -> Self {
        let left = V::deserialize(GenericArray::clone_from_slice(&buf[..V::Size::USIZE]));
        let right = V::deserialize(GenericArray::clone_from_slice(&buf[V::Size::USIZE..]));

        Self::new(left, right)
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::XorShare;
    use crate::bits::{BitArray40, Serializable};

    use generic_array::GenericArray;

    fn secret_share(
        a: u128,
        b: u128,
        c: u128,
    ) -> (
        XorShare<BitArray40>,
        XorShare<BitArray40>,
        XorShare<BitArray40>,
    ) {
        (
            XorShare::new(
                BitArray40::try_from(a).unwrap(),
                BitArray40::try_from(b).unwrap(),
            ),
            XorShare::new(
                BitArray40::try_from(b).unwrap(),
                BitArray40::try_from(c).unwrap(),
            ),
            XorShare::new(
                BitArray40::try_from(c).unwrap(),
                BitArray40::try_from(a).unwrap(),
            ),
        )
    }

    fn assert_valid_secret_sharing(
        res1: &XorShare<BitArray40>,
        res2: &XorShare<BitArray40>,
        res3: &XorShare<BitArray40>,
    ) {
        assert_eq!(res1.1, res2.0);
        assert_eq!(res2.1, res3.0);
        assert_eq!(res3.1, res1.0);
    }

    fn assert_secret_shared_value(
        a1: &XorShare<BitArray40>,
        a2: &XorShare<BitArray40>,
        a3: &XorShare<BitArray40>,
        expected_value: u128,
    ) {
        assert_eq!(
            a1.0 ^ a2.0 ^ a3.0,
            BitArray40::try_from(expected_value).unwrap()
        );
        assert_eq!(
            a1.1 ^ a2.1 ^ a3.1,
            BitArray40::try_from(expected_value).unwrap()
        );
    }

    fn xor_test_case(a: (u128, u128, u128), b: (u128, u128, u128), expected_output: u128) {
        let (a1, a2, a3) = secret_share(a.0, a.1, a.2);
        let (b1, b2, b3) = secret_share(b.0, b.1, b.2);

        let res1 = a1 ^ &b1;
        let res2 = a2 ^ &b2;
        let res3 = a3 ^ &b3;

        assert_valid_secret_sharing(&res1, &res2, &res3);
        assert_secret_shared_value(&res1, &res2, &res3, expected_output);
    }

    #[test]
    fn test_simple_xor() {
        xor_test_case((0, 0, 0), (0, 0, 0), 0);
        xor_test_case((1, 1, 1), (1, 1, 1), 0);

        xor_test_case((10, 0, 0), (12, 0, 0), 6);
        xor_test_case((10, 0, 0), (0, 12, 0), 6);
        xor_test_case((10, 0, 0), (0, 0, 12), 6);

        xor_test_case((0, 10, 0), (12, 0, 0), 6);
        xor_test_case((0, 10, 0), (0, 12, 0), 6);
        xor_test_case((0, 10, 0), (0, 0, 12), 6);

        xor_test_case((0, 0, 10), (12, 0, 0), 6);
        xor_test_case((0, 0, 10), (0, 12, 0), 6);
        xor_test_case((0, 0, 10), (0, 0, 12), 6);

        xor_test_case((163, 202, 92), (172, 21, 199), 75);
    }

    #[test]
    fn serde() {
        let share = XorShare::new(
            BitArray40::try_from(1u128 << 25).unwrap(),
            BitArray40::try_from(1u128 << 15).unwrap(),
        );

        let mut buf = GenericArray::default();
        share.clone().serialize(&mut buf);

        assert_eq!(share, XorShare::deserialize(buf));
    }
}
