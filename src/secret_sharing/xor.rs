use bitvec::prelude::*;
use std::{
    fmt::Debug,
    ops::{BitXor, BitXorAssign, Index},
};

#[derive(Clone, Copy, Debug)]
pub struct XorReplicated {
    left: u64,
    right: u64,
}

impl XorReplicated {
    #[must_use]
    pub fn new(left: u64, right: u64) -> Self {
        Self { left, right }
    }

    #[must_use]
    pub fn left(&self) -> u64 {
        self.left
    }

    #[must_use]
    pub fn right(&self) -> u64 {
        self.right
    }
}

/// XOR secret share.
///
/// Bits are stored in the Little-Endian format. Accessing the first element
/// like `s[0]` will return the LSB.
///
/// ## Example
/// ```
/// use raw_ipa::secret_sharing::XorSecretShare;
///
/// let s = XorSecretShare::<64>::from(2_u128);
/// let b0 = s[0];
/// let b1 = s[1];
///
/// assert_eq!(b0, 0);
/// assert_eq!(b1, 1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct XorSecretShare<const N: usize>(BitVec<u8, Lsb0>);

// BitVec uses `usize` as its default store type in memory. Using `u8`
// here allows us to store bits larger than 32 but less than 64 most
// effectively (i.e., 40-bit = 5 * `u8` blocks).

impl<const N: usize> XorSecretShare<N> {
    const BITS: usize = N;
    const SIZE_IN_BYTES: usize = Self::BITS / 8;

    #[allow(dead_code)]
    #[must_use]
    pub fn new(v: BitVec<u8, Lsb0>) -> Self {
        Self(v)
    }

    #[must_use]
    pub fn zero() -> Self {
        Self(BitVec::from_element(0))
    }
}

impl<const N: usize> BitXor for XorSecretShare<N> {
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self ^= rhs;
        self
    }
}

impl<const N: usize> BitXorAssign for XorSecretShare<N> {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self.0.as_mut_bitslice() ^= rhs.0;
    }
}

/// Converts from `u128` to `XorSecretShare`. If you wish to create a share
/// that holds more than 128 bits, use `XorSecretShare::new()` with `bitvec!`
/// instead.
impl<const N: usize, T: Into<u128>> From<T> for XorSecretShare<N> {
    fn from(v: T) -> Self {
        Self(BitVec::from_slice(
            &v.into().to_le_bytes()[0..Self::SIZE_IN_BYTES],
        ))
    }
}

impl<const N: usize> Index<usize> for XorSecretShare<N> {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        if self.0.as_bitslice()[index] {
            &1
        } else {
            &0
        }
    }
}

impl<const N: usize> Default for XorSecretShare<N> {
    fn default() -> Self {
        XorSecretShare::zero()
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::XorSecretShare;
    use bitvec::prelude::*;
    use rand::{thread_rng, Rng};

    fn secret_share(
        a: u128,
        b: u128,
        c: u128,
    ) -> (XorSecretShare<40>, XorSecretShare<40>, XorSecretShare<40>) {
        (
            XorSecretShare::from(a),
            XorSecretShare::from(b),
            XorSecretShare::from(c),
        )
    }

    #[test]
    pub fn basic() {
        assert_eq!(
            XorSecretShare::<8>::zero().0.as_bitslice(),
            bits![0, 0, 0, 0, 0, 0, 0, 0],
        );

        assert_eq!(
            XorSecretShare::<8>::from(1_u128).0.as_bitslice(),
            bits![1, 0, 0, 0, 0, 0, 0, 0],
        );

        assert_eq!(
            XorSecretShare::<8>::from(65793_u128).0.as_bitslice(),
            bits![1, 0, 0, 0, 0, 0, 0, 0],
        );

        assert_eq!(
            XorSecretShare::<24>::from(65793_u128).0.as_bitslice(),
            bits![1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
        );
    }

    #[test]
    pub fn index() {
        let byte: u8 = 0b1010_1010;
        let s = XorSecretShare::<8>::from(byte);
        assert_eq!(s[0], 0);
        assert_eq!(s[1], 1);
        assert_eq!(s[2], 0);
        assert_eq!(s[3], 1);
        assert_eq!(s[4], 0);
        assert_eq!(s[5], 1);
        assert_eq!(s[6], 0);
        assert_eq!(s[7], 1);
    }

    #[test]
    pub fn xor_secret_sharing() {
        let mut rng = thread_rng();
        for _ in 0..1000 {
            let secret = rng.gen::<u128>();
            let a = rng.gen::<u128>();
            let b = rng.gen::<u128>();
            let c = secret ^ a ^ b;
            let (s0, s1, s2) = secret_share(a, b, c);
            assert_eq!(XorSecretShare::from(secret), s0 ^ s1 ^ s2);
        }
    }
}
