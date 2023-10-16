use curve25519_dalek::{
    constants,
    ristretto::{CompressedRistretto, RistrettoPoint},
    Scalar,
};
use generic_array::GenericArray;
use hkdf::Hkdf;
use sha2::Sha256;
use typenum::U32;

use crate::{
    error::Error,
    ff::{ec_prime_field::Fp25519, Field, Serializable},
    secret_sharing::{Block, SharedValue},
};

impl Block for CompressedRistretto {
    type Size = U32;
}

///ristretto point for curve 25519
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct RP25519(<Self as SharedValue>::Storage);

/// using compressed ristretto point, Zero is generator of the curve, i.e. g^0
impl SharedValue for RP25519 {
    type Storage = CompressedRistretto;
    const BITS: u32 = 256;
    const ZERO: Self = Self(constants::RISTRETTO_BASEPOINT_COMPRESSED);
}

impl Serializable for RP25519 {
    type Size = <<RP25519 as SharedValue>::Storage as Block>::Size;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        *buf.as_mut() = self.0.to_bytes();
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        RP25519(CompressedRistretto::from_slice(buf).unwrap())
    }
}

impl rand::distributions::Distribution<RP25519> for rand::distributions::Standard {
    fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> RP25519 {
        //Fp25519(Scalar::random(rng: &mut R))
        let mut scalar_bytes = [0u8; 64];
        rng.fill_bytes(&mut scalar_bytes);
        RP25519(RistrettoPoint::from_uniform_bytes(&scalar_bytes).compress())
    }
}

impl std::ops::Add for RP25519 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self((self.0.decompress().unwrap() + rhs.0.decompress().unwrap()).compress())
    }
}

impl std::ops::AddAssign for RP25519 {
    #[allow(clippy::assign_op_pattern)]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl std::ops::Neg for RP25519 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.decompress().unwrap().neg().compress())
    }
}

impl std::ops::Sub for RP25519 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self((self.0.decompress().unwrap() - rhs.0.decompress().unwrap()).compress())
    }
}

impl std::ops::SubAssign for RP25519 {
    #[allow(clippy::assign_op_pattern)]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

///Scalar Multiplication
///<'a, 'b> `std::ops::Mul<&'b"` Fp25519 for &'a
impl RP25519 {

    /// # Errors
    /// Propagates errors from decompressing invalid curve point
    pub fn s_mul(self, rhs: Fp25519) -> Result<RP25519, Error> {
        self.0
            .decompress()
            .map_or(Err(Error::DecompressingInvalidCurvePoint), |x| {
                Ok((x * Scalar::from(rhs)).compress().into())
            })
    }
}

///do not use
impl std::ops::Mul for RP25519 {
    type Output = Self;

    fn mul(self, _rhs: RP25519) -> Self::Output {
        panic!("Two curve points cannot be multiplied! Do not use *, *= for RP25519 or secret shares of RP25519");
    }
}

///do not use
impl std::ops::MulAssign for RP25519 {
    fn mul_assign(&mut self, _rhs: RP25519) {
        panic!("Two curve points cannot be multiplied! Do not use *, *= for RP25519 or secret shares of RP25519");
    }
}

impl From<Scalar> for RP25519 {
    fn from(s: Scalar) -> Self {
        RP25519(RistrettoPoint::mul_base(&s).compress())
    }
}

impl From<Fp25519> for RP25519 {
    fn from(s: Fp25519) -> Self {
        RP25519(RistrettoPoint::mul_base(&s.into()).compress())
    }
}

impl From<CompressedRistretto> for RP25519 {
    fn from(s: CompressedRistretto) -> Self {
        RP25519(s)
    }
}

impl From<RP25519> for CompressedRistretto {
    fn from(s: RP25519) -> Self {
        s.0
    }
}

macro_rules! cp_hash_impl {
    ( $u_type:ty, $byte_size:literal) => {
        impl From<RP25519> for $u_type {
            fn from(s: RP25519) -> Self {
                let hk = Hkdf::<Sha256>::new(None, s.0.as_bytes());
                let mut okm = [0u8; $byte_size];
                //error invalid length from expand only happens when okm is very large
                hk.expand(&[], &mut okm).unwrap();
                <$u_type>::from_le_bytes(okm)
            }
        }

        impl From<$u_type> for RP25519 {
            fn from(s: $u_type) -> Self {
                let hk = Hkdf::<Sha256>::new(None, &s.to_le_bytes());
                let mut okm = [0u8; 32];
                //error invalid length from expand only happens when okm is very large
                hk.expand(&[], &mut okm).unwrap();
                RP25519::deserialize(&okm.into())
            }
        }
    };
}

cp_hash_impl!(u64, 8);

cp_hash_impl!(u32, 4);

/// Daniel had to implement this since Reveal wants it, prefer not to, I dont understand why it is
/// actually needed there, maybe to upgrade it to malicious? but it still shouldn't be needed
impl Field for RP25519 {
    const ONE: RP25519 = Self(constants::RISTRETTO_BASEPOINT_COMPRESSED);

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
        RP25519::deserialize(&okm.into())
    }
}

impl TryFrom<u128> for RP25519 {
    type Error = crate::error::Error;

    fn try_from(v: u128) -> Result<Self, Self::Error> {
        let mut bits = [0u8; 32];
        bits[..].copy_from_slice(&v.to_le_bytes());
        let f: RP25519 = RP25519::ONE;
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
        ff::{curve_points::RP25519, ec_prime_field::Fp25519, Serializable, field::Field},
    };

    #[test]
    fn serde_25519() {
        let input: [u8; 32] = [
            0x01, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
            0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
            0x00, 0x00, 0x00, 0x00,
        ];
        let mut output: GenericArray<u8, U32> = [0u8; 32].into();
        let a = RP25519::deserialize(&input.into());
        assert_eq!(a.0.as_bytes()[..32], input);
        a.serialize(&mut output);
        assert_eq!(a.0.as_bytes()[..32], output.as_slice()[..32]);
        assert_eq!(input, output.as_slice()[..32]);
    }

    #[test]
    fn scalar_to_point() {
        let a = Scalar::ONE;
        let b: RP25519 = a.into();
        let d: Fp25519 = a.into();
        let c: RP25519 = RP25519::from(d);
        assert_eq!(b, RP25519::ONE);
        assert_eq!(c, RP25519::ONE);
    }

    #[test]
    fn curve_arithmetics() {
        let mut rng = thread_rng();
        let fp_a = rng.gen::<Fp25519>();
        let fp_b = rng.gen::<Fp25519>();
        let fp_c = fp_a + fp_b;
        let fp_d = RP25519::from(fp_a) + RP25519::from(fp_b);
        assert_eq!(fp_d, RP25519::from(fp_c));
        assert_ne!(fp_d, RP25519::ONE);
        let fp_e = rng.gen::<Fp25519>();
        let fp_f = rng.gen::<Fp25519>();
        let fp_g = fp_e * fp_f;
        let fp_h = RP25519::from(fp_e).s_mul(fp_f).unwrap();
        assert_eq!(fp_h, RP25519::from(fp_g));
        assert_ne!(fp_h, RP25519::ONE);
    }

    #[test]
    fn curve_point_to_hash() {
        let mut rng = thread_rng();
        let fp_a = rng.gen::<RP25519>();
        assert_ne!(0u64, u64::from(fp_a));
        assert_ne!(0u32, u32::from(fp_a));
    }
}
