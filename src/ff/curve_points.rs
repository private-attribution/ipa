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
    ff::{ec_prime_field::Fp25519, Serializable},
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
        RP25519(CompressedRistretto((*buf).into()))
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
    ( $u_type:ty) => {
        impl From<RP25519> for $u_type {
            fn from(s: RP25519) -> Self {
                let hk = Hkdf::<Sha256>::new(None, s.0.as_bytes());
                let mut okm = <$u_type>::MIN.to_le_bytes();
                //error invalid length from expand only happens when okm is very large
                hk.expand(&[], &mut okm).unwrap();
                <$u_type>::from_le_bytes(okm)
            }
        }
    };
}

cp_hash_impl!(u128);

cp_hash_impl!(u64);

#[cfg(test)]
cp_hash_impl!(u32);

#[cfg(test)]
impl rand::distributions::Distribution<RP25519> for rand::distributions::Standard {
    fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> RP25519 {
        let mut scalar_bytes = [0u8; 64];
        rng.fill_bytes(&mut scalar_bytes);
        RP25519(RistrettoPoint::from_uniform_bytes(&scalar_bytes).compress())
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use curve25519_dalek::{constants, scalar::Scalar};
    use generic_array::GenericArray;
    use rand::{thread_rng, Rng};
    use typenum::U32;

    use crate::ff::{curve_points::RP25519, ec_prime_field::Fp25519, Serializable};

    #[test]
    fn serde_25519() {
        let mut rng = thread_rng();
        let input = rng.gen::<RP25519>();
        let mut a: GenericArray<u8, U32> = [0u8; 32].into();
        input.serialize(&mut a);
        let output = RP25519::deserialize(&a);
        assert_eq!(input, output);
    }

    #[test]
    fn scalar_to_point() {
        let a = Scalar::ONE;
        let b: RP25519 = a.into();
        let d: Fp25519 = a.into();
        let c: RP25519 = RP25519::from(d);
        assert_eq!(b, RP25519(constants::RISTRETTO_BASEPOINT_COMPRESSED));
        assert_eq!(c, RP25519(constants::RISTRETTO_BASEPOINT_COMPRESSED));
    }

    #[test]
    fn curve_arithmetics() {
        let mut rng = thread_rng();
        let fp_a = rng.gen::<Fp25519>();
        let fp_b = rng.gen::<Fp25519>();
        let fp_c = fp_a + fp_b;
        let fp_d = RP25519::from(fp_a) + RP25519::from(fp_b);
        assert_eq!(fp_d, RP25519::from(fp_c));
        assert_ne!(fp_d, RP25519(constants::RISTRETTO_BASEPOINT_COMPRESSED));
        let fp_e = rng.gen::<Fp25519>();
        let fp_f = rng.gen::<Fp25519>();
        let fp_g = fp_e * fp_f;
        let fp_h = RP25519::from(fp_e).s_mul(fp_f).unwrap();
        assert_eq!(fp_h, RP25519::from(fp_g));
        assert_ne!(fp_h, RP25519(constants::RISTRETTO_BASEPOINT_COMPRESSED));
    }

    #[test]
    fn curve_point_to_hash() {
        let mut rng = thread_rng();
        let fp_a = rng.gen::<RP25519>();
        assert_ne!(0u64, u64::from(fp_a));
        assert_ne!(0u32, u32::from(fp_a));
    }
}
