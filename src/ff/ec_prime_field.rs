use curve25519_dalek::scalar::Scalar;
use generic_array::GenericArray;
use hkdf::Hkdf;
use sha2::Sha256;
use typenum::U32;

use crate::{
    ff::{Field, Serializable},
    secret_sharing::{Block, SharedValue},
};

impl Block for Scalar {
    type Size = U32;
}

///implements the Scalar field for elliptic curve 25519
/// we use elements in Fp25519 to generate curve points and operate on the curve
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Fp25519(<Self as SharedValue>::Storage);

impl Fp25519 {
    pub const ONE: Self = Self(Scalar::ONE);

    ///allow invert for scalars, i.e. computes 1/a mod p
    ///# Panics
    /// Panics when self is zero
    #[must_use]
    pub fn invert(&self) -> Fp25519 {
        assert_ne!(*self, Fp25519::ZERO);
        Fp25519(self.0.invert())
    }
}

///trait for secret sharing
impl SharedValue for Fp25519 {
    type Storage = Scalar;
    const BITS: u32 = 256;
    const ZERO: Self = Self(Scalar::ZERO);
}

///conversion to Scalar struct of `curve25519_dalek`
impl From<Fp25519> for Scalar {
    fn from(s: Fp25519) -> Self {
        s.0
    }
}

impl Serializable for Fp25519 {
    type Size = <<Fp25519 as SharedValue>::Storage as Block>::Size;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        *buf.as_mut() = self.0.to_bytes();
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        Fp25519(Scalar::from_bytes_mod_order((*buf).into()))
    }
}

///generate random elements in Fp25519
impl rand::distributions::Distribution<Fp25519> for rand::distributions::Standard {
    fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> Fp25519 {
        let mut scalar_bytes = [0u8; 32];
        rng.fill_bytes(&mut scalar_bytes);
        Fp25519(Scalar::from_bytes_mod_order(scalar_bytes))
    }
}

impl std::ops::Add for Fp25519 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl std::ops::AddAssign for Fp25519 {
    #[allow(clippy::assign_op_pattern)]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl std::ops::Neg for Fp25519 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl std::ops::Sub for Fp25519 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl std::ops::SubAssign for Fp25519 {
    #[allow(clippy::assign_op_pattern)]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl std::ops::Mul for Fp25519 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl std::ops::MulAssign for Fp25519 {
    #[allow(clippy::assign_op_pattern)]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl From<Scalar> for Fp25519 {
    fn from(s: Scalar) -> Self {
        Fp25519(s)
    }
}

///conversion from and to unsigned integers, preserving entropy, for testing purposes only
#[cfg(test)]
macro_rules! sc_hash_impl {
    ( $u_type:ty) => {
        impl From<Fp25519> for $u_type {
            fn from(s: Fp25519) -> Self {
                use hkdf::Hkdf;
                use sha2::Sha256;
                let hk = Hkdf::<Sha256>::new(None, s.0.as_bytes());
                let mut okm = <$u_type>::MIN.to_le_bytes();
                //error invalid length from expand only happens when okm is very large
                hk.expand(&[], &mut okm).unwrap();
                <$u_type>::from_le_bytes(okm)
            }
        }

        impl From<$u_type> for Fp25519 {
            fn from(s: $u_type) -> Self {
                use hkdf::Hkdf;
                use sha2::Sha256;
                let hk = Hkdf::<Sha256>::new(None, &s.to_le_bytes());
                let mut okm = [0u8; 32];
                //error invalid length from expand only happens when okm is very large
                hk.expand(&[], &mut okm).unwrap();
                Fp25519::deserialize(&okm.into())
            }
        }
    };
}

#[cfg(test)]
sc_hash_impl!(u64);

///implement Field because required by PRSS
impl Field for Fp25519 {
    const ONE: Fp25519 = Fp25519::ONE;

    ///both following methods are based on hashing and do not allow to actually convert elements in Fp25519
    /// from or into u128. However it is sufficient to generate random elements in Fp25519
    fn as_u128(&self) -> u128 {
        let hk = Hkdf::<Sha256>::new(None, self.0.as_bytes());
        let mut okm = [0u8; 16];
        //error invalid length from expand only happens when okm is very large
        hk.expand(&[], &mut okm).unwrap();
        u128::from_le_bytes(okm)
    }

    ///PRSS uses `truncate_from function`, we need to expand the u128 using a PRG (Sha256) to a [u8;32]
    fn truncate_from<T: Into<u128>>(v: T) -> Self {
        let hk = Hkdf::<Sha256>::new(None, &v.into().to_le_bytes());
        let mut okm = [0u8; 32];
        //error invalid length from expand only happens when okm is very large
        hk.expand(&[], &mut okm).unwrap();
        Fp25519::deserialize(&okm.into())
    }
}

///implement `TryFrom` since required by Field
impl TryFrom<u128> for Fp25519 {
    type Error = crate::error::Error;

    fn try_from(v: u128) -> Result<Self, Self::Error> {
        let mut bits = [0u8; 32];
        bits[..].copy_from_slice(&v.to_le_bytes());
        let f: Fp25519 = Fp25519::ONE;
        f.serialize((&mut bits).into());
        Ok(f)
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use curve25519_dalek::scalar::Scalar;
    use generic_array::GenericArray;
    use rand::{thread_rng, Rng};
    use typenum::U32;

    use crate::{
        ff::{ec_prime_field::Fp25519, Serializable},
        secret_sharing::SharedValue,
    };

    sc_hash_impl!(u32);

    ///test serialize and deserialize
    #[test]
    fn serde_25519() {
        let mut rng = thread_rng();
        let input = rng.gen::<Fp25519>();
        let mut a: GenericArray<u8, U32> = [0u8; 32].into();
        input.serialize(&mut a);
        let output = Fp25519::deserialize(&a);
        assert_eq!(input, output);
    }

    ///test simple arithmetics to check that `curve25519_dalek` is used correctly
    #[test]
    fn simple_arithmetics_25519() {
        let a = Fp25519(Scalar::from_bytes_mod_order([
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]));
        let b = Fp25519(Scalar::from_bytes_mod_order([
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]));
        let d = Fp25519(Scalar::from_bytes_mod_order([
            0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]));
        let e = Fp25519(Scalar::from_bytes_mod_order([
            0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]));
        let cc = b - a;
        let dc = a + b;
        let ec = a * b;
        assert_eq!(cc, Fp25519::ONE);
        assert_eq!(dc, d);
        assert_eq!(ec, e);
    }

    ///test random field element generation (!= 0)
    #[test]
    fn simple_random_25519() {
        let mut rng = thread_rng();
        assert_ne!(Fp25519::ZERO, rng.gen::<Fp25519>());
    }

    ///test inversion for field elements
    #[test]
    fn invert_25519() {
        let mut rng = thread_rng();
        let a = rng.gen::<Fp25519>();
        let ia = a.invert();
        assert_eq!(a * ia, Fp25519(Scalar::ONE));
    }
}
