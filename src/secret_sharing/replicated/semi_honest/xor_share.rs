use crate::{
    ff::{GaloisField, Serializable},
    secret_sharing::{
        replicated::ReplicatedSecretSharing, Bitwise as BitwiseSecretSharing,
        Linear as LinearSecretSharing, SecretSharing,
    },
};
use aes::cipher::generic_array::GenericArray;

use generic_array::ArrayLength;
use typenum::Unsigned;

use std::{
    fmt::{Debug, Formatter},
    ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign},
};

// TODO (taikiy): Merge `AddtiveShare` and `XorShare` implementations
// We'll need to merge the two to remove dup code, but implementing `Reshare` for `AdditiveShare<SharedValue>`
// and `AdditiveShare<GaloisField>` will require further refactoring. Since we don't know what `Reshare` might
// look like for Galois Field shares, I'm differing the merge to after the `Reshare` implementation.

#[derive(Clone, PartialEq, Eq)]
pub struct XorShare<V: GaloisField>(V, V);

impl<V: GaloisField> SecretSharing<V> for XorShare<V> {
    const ZERO: Self = XorShare::ZERO;
}

impl<V: GaloisField> LinearSecretSharing<V> for XorShare<V> {}

impl<V: GaloisField> BitwiseSecretSharing<V> for XorShare<V> {}

impl<V: GaloisField + Debug> Debug for XorShare<V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "({:?}, {:?})", self.0, self.1)
    }
}

impl<V: GaloisField> Default for XorShare<V> {
    fn default() -> Self {
        XorShare::new(V::ZERO, V::ZERO)
    }
}

impl<V: GaloisField> XorShare<V> {
    pub fn as_tuple(&self) -> (V, V) {
        (self.0, self.1)
    }

    /// Replicated secret share where both left and right values are `V::ZERO`
    pub const ZERO: XorShare<V> = Self(V::ZERO, V::ZERO);
}

impl<V: GaloisField> ReplicatedSecretSharing<V> for XorShare<V> {
    fn new(a: V, b: V) -> Self {
        Self(a, b)
    }

    fn left(&self) -> V {
        self.0
    }

    fn right(&self) -> V {
        self.1
    }
}

impl<V: GaloisField> Add<Self> for &XorShare<V> {
    type Output = XorShare<V>;

    fn add(self, rhs: Self) -> Self::Output {
        XorShare(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl<V: GaloisField> Add<&Self> for XorShare<V> {
    type Output = Self;

    fn add(mut self, rhs: &Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<V: GaloisField> AddAssign<&Self> for XorShare<V> {
    fn add_assign(&mut self, rhs: &Self) {
        self.0 += rhs.0;
        self.1 += rhs.1;
    }
}

impl<V: GaloisField> Neg for XorShare<V> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0, -self.1)
    }
}

impl<V: GaloisField> Sub<Self> for &XorShare<V> {
    type Output = XorShare<V>;

    fn sub(self, rhs: Self) -> Self::Output {
        XorShare(self.0 - rhs.0, self.1 - rhs.1)
    }
}

impl<V: GaloisField> Sub<&Self> for XorShare<V> {
    type Output = Self;

    fn sub(mut self, rhs: &Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl<V: GaloisField> SubAssign<&Self> for XorShare<V> {
    fn sub_assign(&mut self, rhs: &Self) {
        self.0 -= rhs.0;
        self.1 -= rhs.1;
    }
}

impl<V: GaloisField> Mul<V> for XorShare<V> {
    type Output = Self;

    fn mul(self, rhs: V) -> Self::Output {
        Self(self.0 * rhs, self.1 * rhs)
    }
}

impl<V: GaloisField> Serializable for XorShare<V>
where
    V::Size: Add<V::Size>,
    <V::Size as Add<V::Size>>::Output: ArrayLength<u8>,
{
    /// This constraint means that the serialized size must be `V::SIZE` + `V::SIZE`, i.e. `2 * V::SIZE`
    type Size = <V::Size as Add<V::Size>>::Output;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        let (left, right) = buf.split_at_mut(V::Size::USIZE);
        self.left().serialize(GenericArray::from_mut_slice(left));
        self.right().serialize(GenericArray::from_mut_slice(right));
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        let left = V::deserialize(GenericArray::from_slice(&buf[..V::Size::USIZE]));
        let right = V::deserialize(GenericArray::from_slice(&buf[V::Size::USIZE..]));

        Self::new(left, right)
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::XorShare;
    use crate::{
        ff::{GaloisField, Gf40Bit, Serializable},
        secret_sharing::replicated::ReplicatedSecretSharing,
    };

    use generic_array::GenericArray;

    fn secret_share(
        a: u128,
        b: u128,
        c: u128,
    ) -> (XorShare<Gf40Bit>, XorShare<Gf40Bit>, XorShare<Gf40Bit>) {
        (
            XorShare::new(Gf40Bit::try_from(a).unwrap(), Gf40Bit::try_from(b).unwrap()),
            XorShare::new(Gf40Bit::try_from(b).unwrap(), Gf40Bit::try_from(c).unwrap()),
            XorShare::new(Gf40Bit::try_from(c).unwrap(), Gf40Bit::try_from(a).unwrap()),
        )
    }

    fn assert_valid_secret_sharing(
        res1: &XorShare<Gf40Bit>,
        res2: &XorShare<Gf40Bit>,
        res3: &XorShare<Gf40Bit>,
    ) {
        assert_eq!(res1.1, res2.0);
        assert_eq!(res2.1, res3.0);
        assert_eq!(res3.1, res1.0);
    }

    fn assert_secret_shared_value(
        a1: &XorShare<Gf40Bit>,
        a2: &XorShare<Gf40Bit>,
        a3: &XorShare<Gf40Bit>,
        expected_value: u128,
    ) {
        assert_eq!(
            a1.0 + a2.0 + a3.0,
            Gf40Bit::try_from(expected_value).unwrap()
        );
        assert_eq!(
            a1.1 + a2.1 + a3.1,
            Gf40Bit::try_from(expected_value).unwrap()
        );
    }

    fn addition_test_case(a: (u128, u128, u128), b: (u128, u128, u128), expected_output: u128) {
        let (a1, a2, a3) = secret_share(a.0, a.1, a.2);
        let (b1, b2, b3) = secret_share(b.0, b.1, b.2);

        // Compute a + b
        let res1 = a1 + &b1;
        let res2 = a2 + &b2;
        let res3 = a3 + &b3;

        assert_valid_secret_sharing(&res1, &res2, &res3);
        assert_secret_shared_value(&res1, &res2, &res3, expected_output);
    }

    #[test]
    fn test_simple_addition() {
        // Addition in Galois Fields is XOR
        addition_test_case((0, 0, 0), (0, 0, 0), 0);
        addition_test_case((1, 1, 1), (1, 1, 1), 0);

        addition_test_case((10, 0, 0), (12, 0, 0), 6);
        addition_test_case((10, 0, 0), (0, 12, 0), 6);
        addition_test_case((10, 0, 0), (0, 0, 12), 6);

        addition_test_case((0, 10, 0), (12, 0, 0), 6);
        addition_test_case((0, 10, 0), (0, 12, 0), 6);
        addition_test_case((0, 10, 0), (0, 0, 12), 6);

        addition_test_case((0, 0, 10), (12, 0, 0), 6);
        addition_test_case((0, 0, 10), (0, 12, 0), 6);
        addition_test_case((0, 0, 10), (0, 0, 12), 6);

        addition_test_case((163, 202, 92), (172, 21, 199), 75);
    }

    fn subtraction_test_case(a: (u128, u128, u128), b: (u128, u128, u128), expected_output: u128) {
        let (a1, a2, a3) = secret_share(a.0, a.1, a.2);
        let (b1, b2, b3) = secret_share(b.0, b.1, b.2);

        // Compute a - b
        let res1 = a1 - &b1;
        let res2 = a2 - &b2;
        let res3 = a3 - &b3;

        assert_valid_secret_sharing(&res1, &res2, &res3);
        assert_secret_shared_value(&res1, &res2, &res3, expected_output);
    }

    #[test]
    fn test_simple_subtraction() {
        // Subtraction in Galois Fields is XOR (same as addition).
        subtraction_test_case((0, 0, 0), (0, 0, 0), 0);
        subtraction_test_case((1, 1, 1), (1, 1, 1), 0);

        subtraction_test_case((10, 0, 0), (12, 0, 0), 6);
        subtraction_test_case((10, 0, 0), (0, 12, 0), 6);
        subtraction_test_case((10, 0, 0), (0, 0, 12), 6);

        subtraction_test_case((0, 10, 0), (12, 0, 0), 6);
        subtraction_test_case((0, 10, 0), (0, 12, 0), 6);
        subtraction_test_case((0, 10, 0), (0, 0, 12), 6);

        subtraction_test_case((0, 0, 10), (12, 0, 0), 6);
        subtraction_test_case((0, 0, 10), (0, 12, 0), 6);
        subtraction_test_case((0, 0, 10), (0, 0, 12), 6);

        subtraction_test_case((163, 202, 92), (172, 21, 199), 75);
    }

    fn mul_by_constant_test_case(a: (u128, u128, u128), c: u128, expected_output: u128) {
        let (a1, a2, a3) = secret_share(a.0, a.1, a.2);

        // Compute a * c
        let res1 = a1 * Gf40Bit::truncate_from(c);
        let res2 = a2 * Gf40Bit::truncate_from(c);
        let res3 = a3 * Gf40Bit::truncate_from(c);

        assert_valid_secret_sharing(&res1, &res2, &res3);
        assert_secret_shared_value(&res1, &res2, &res3, expected_output);
    }

    #[test]
    fn test_mul_by_constant() {
        // This test tests mul by constant for GF(2^40)
        // The Irreducible Polynomial (P) for GF(2^40) is:
        //
        // x^40 + x^5 + x^3 + x^2 + 1
        //
        // or in the binary notation
        //
        // 0b1_0000_0000_0000_0000_0000_0000_0000_0000_0010_1101_u128

        // 1 * 1 / P = 1 / P = 1
        mul_by_constant_test_case((1, 0, 0), 1, 1);
        mul_by_constant_test_case((0, 1, 0), 1, 1);
        mul_by_constant_test_case((0, 0, 1), 1, 1);

        // 0 * 1 / P = 0 / P = 0
        mul_by_constant_test_case((0, 0, 0), 1, 0);
    }

    #[test]
    fn serde() {
        let share = XorShare::new(
            Gf40Bit::try_from(1u128 << 25).unwrap(),
            Gf40Bit::try_from(1u128 << 15).unwrap(),
        );

        let mut buf = GenericArray::default();
        share.serialize(&mut buf);

        assert_eq!(share, XorShare::deserialize(&buf));
    }
}
