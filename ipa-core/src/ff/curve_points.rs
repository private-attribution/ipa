use curve25519_dalek::{constants, ristretto::{CompressedRistretto, RistrettoPoint}, Scalar};
use generic_array::GenericArray;
use ipa_metrics::counter;
use typenum::{U128, U32};

use crate::{
    ff::{ec_prime_field::Fp25519, Serializable},
    impl_shared_value_common,
    protocol::ipa_prf::PRF_CHUNK,
    secret_sharing::{Block, SharedValue, StdArray, Vectorizable},
};

impl Block for CompressedRistretto {
    type Size = U32;
}

///ristretto point for curve 25519,
/// we store it in compressed format since it is 3 times smaller and we do a limited amount of
/// arithmetic operations on the curve points
///
/// We use ristretto points such that we have a prime order elliptic curve,
/// This is needed for the Dodis Yampolski PRF
///
/// decompressing invalid curve points will cause panics,
/// since we always generate curve points from scalars (elements in Fp25519) and
/// only deserialize previously serialized valid points, panics will not occur
/// However, we still added a debug assert to deserialize since values are sent by other servers
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
// make an enum and play
pub struct RP25519(RistrettoPoint);

impl Default for RP25519 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl Block for RistrettoPoint {
    type Size = U128;
}

/// Implementing trait for secret sharing
impl SharedValue for RP25519 {
    type Storage = RistrettoPoint;
    const BITS: u32 = 1024;
    const ZERO: Self = Self(constants::RISTRETTO_BASEPOINT_POINT);

    impl_shared_value_common!();
}

pub const DECOMPRESS_OP: &str = "RP25519.decompress";
pub const DECOMPRESS_ADD_OP: &str = "RP25519.decompress.add";
pub const DECOMPRESS_MUL_OP: &str = "RP25519.decompress.mul";
pub const DECOMPRESS_DESER_OP: &str = "RP25519.decompress.deserialize";
pub const COMPRESS_OP: &str = "RP25519.compress";
pub const COMPRESS_HASH_OP: &str = "RP25519.compress.hash";
pub const COMPRESS_SER_OP: &str = "RP25519.compress.serialize";
pub const COMPRESS_FROM_SCALAR_OP: &str = "RP25519.compress.from.scalar";
pub const COMPRESS_FROM_FP_OP: &str = "RP25519.compress.from.fp";

impl Vectorizable<1> for RP25519 {
    type Array = StdArray<Self, 1>;
}

impl Vectorizable<PRF_CHUNK> for RP25519 {
    type Array = StdArray<Self, PRF_CHUNK>;
}

#[derive(thiserror::Error, Debug)]
#[error("{0:?} is not the canonical encoding of a Ristretto point.")]
pub struct NonCanonicalEncoding(CompressedRistretto);

#[derive(Copy, Clone, Debug)]
pub struct CompressedRp25519(CompressedRistretto);
impl Block for CompressedRp25519 {
    type Size = U32;
}

impl Serializable for CompressedRp25519 {
    type Size = <Self as Block>::Size;
    type DeserializationError = NonCanonicalEncoding;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        *buf.as_mut() = self.0.to_bytes();
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserializationError> {
        let point = CompressedRistretto((*buf).into());
        Ok(CompressedRp25519(point))
    }
}

impl Serializable for RP25519 {
    type Size = <CompressedRp25519 as Block>::Size;
    type DeserializationError = NonCanonicalEncoding;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        counter!(COMPRESS_OP, 1);
        counter!(COMPRESS_SER_OP, 1);
        let compressed = CompressedRp25519(self.0.compress());
        *buf.as_mut() = compressed.0.to_bytes();
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserializationError> {
        let point = CompressedRistretto((*buf).into());
        counter!(DECOMPRESS_OP, 1);
        counter!(DECOMPRESS_DESER_OP, 1);
        match point.decompress() {
            Some(v) => Ok(Self(v)),
            None => Err(NonCanonicalEncoding(point)),
        }
    }
}

///## Panics
/// Panics when decompressing invalid curve point. This can happen when deserialize curve point
/// from bit array that does not have a valid representation on the curve
impl std::ops::Add for RP25519 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        // counter!(DECOMPRESS_OP, 2);
        // counter!(COMPRESS_OP, 1);
        // counter!(COMPRESS_ADD_OP, 1);
        // counter!(DECOMPRESS_ADD_OP, 2);
        Self(self.0 + rhs.0)
    }
}

impl std::ops::AddAssign for RP25519 {
    #[allow(clippy::assign_op_pattern)]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

///## Panics
/// Panics when decompressing invalid curve point. This can happen when deserialize curve point
/// from bit array that does not have a valid representation on the curve
impl std::ops::Neg for RP25519 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        // counter!(DECOMPRESS_OP, 1);
        // counter!(COMPRESS_OP, 1);
        Self(self.0.neg())
    }
}

///## Panics
/// Panics when decompressing invalid curve point. This can happen when deserialize curve point
/// from bit array that does not have a valid representation on the curve
impl std::ops::Sub for RP25519 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        // counter!(DECOMPRESS_OP, 2);
        // counter!(COMPRESS_OP, 1);
        Self(self.0 - rhs.0)
    }
}

impl std::ops::SubAssign for RP25519 {
    #[allow(clippy::assign_op_pattern)]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

///Scalar Multiplication
/// allows to multiply curve points with scalars from Fp25519
///## Panics
/// Panics when decompressing invalid curve point. This can happen when deserialize curve point
/// from bit array that does not have a valid representation on the curve
impl std::ops::Mul<Fp25519> for RP25519 {
    type Output = Self;

    fn mul(self, rhs: Fp25519) -> Self {
        // counter!(DECOMPRESS_OP, 1);
        // counter!(DECOMPRESS_MUL_OP, 1);
        // counter!(COMPRESS_OP, 1);
        // counter!(COMPRESS_MUL_OP, 1);
        Self(self.0 * Scalar::from(rhs))
    }
}

impl std::ops::MulAssign<Fp25519> for RP25519 {
    #[allow(clippy::assign_op_pattern)]
    fn mul_assign(&mut self, rhs: Fp25519) {
        *self = *self * rhs;
    }
}

impl From<Scalar> for RP25519 {
    fn from(s: Scalar) -> Self {
        // counter!(COMPRESS_OP, 1);
        // counter!(COMPRESS_FROM_SCALAR_OP, 1);
        Self(RistrettoPoint::mul_base(&s))
    }
}

impl From<Fp25519> for RP25519 {
    fn from(s: Fp25519) -> Self {
        // counter!(COMPRESS_OP, 1);
        // counter!(COMPRESS_FROM_FP_OP, 1);
        Self(RistrettoPoint::mul_base(&s.into()))
    }
}

// impl From<CompressedRistretto> for RP25519 {
//     fn from(s: CompressedRistretto) -> Self {
//         RP25519(s)
//     }
// }

// impl From<RP25519> for CompressedRistretto {
//     fn from(s: RP25519) -> Self {
//         s.0
//     }
// }

///allows to convert curve points into unsigned integers, preserving high entropy
macro_rules! cp_hash_impl {
    ( $u_type:ty) => {
        impl From<RP25519> for $u_type {
            fn from(s: RP25519) -> Self {
                use hkdf::Hkdf;
                use sha2::Sha256;
                ipa_metrics::counter!(crate::ff::curve_points::COMPRESS_OP, 1);
                ipa_metrics::counter!(crate::ff::curve_points::COMPRESS_HASH_OP, 1);
                let hk = Hkdf::<Sha256>::new(None, s.0.compress().as_bytes());
                let mut okm = <$u_type>::MIN.to_le_bytes();
                //error invalid length from expand only happens when okm is very large
                hk.expand(&[], &mut okm).unwrap();
                <$u_type>::from_le_bytes(okm)
            }
        }
    };
}

// cp_hash_impl!(u128);
//
cp_hash_impl!(u64);

/// implementing random curve point generation for testing purposes,
/// in the actual IPA protocol, we generate them from scalars, i.e. Fp25519
#[cfg(test)]
impl rand::distributions::Distribution<RP25519> for rand::distributions::Standard {
    fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> RP25519 {
        let mut scalar_bytes = [0u8; 64];
        rng.fill_bytes(&mut scalar_bytes);
        RP25519(RistrettoPoint::from_uniform_bytes(&scalar_bytes))
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use curve25519_dalek::{constants, scalar::Scalar};
    use generic_array::GenericArray;
    use rand::{thread_rng, Rng};
    use typenum::U32;

    use crate::{
        ff::{curve_points::RP25519, ec_prime_field::Fp25519, Serializable},
        secret_sharing::SharedValue,
    };

    cp_hash_impl!(u32);

    ///testing serialize and deserialize
    #[test]
    fn serde_25519() {
        let mut rng = thread_rng();
        let input = rng.gen::<RP25519>();
        let mut a: GenericArray<u8, U32> = [0u8; 32].into();
        input.serialize(&mut a);
        let output = RP25519::deserialize(&a).unwrap();
        assert_eq!(input, output);
    }

    ///testing conversion from scalar to Fp25519 and curve point, i.e. RP25519
    #[test]
    fn scalar_to_point() {
        let a = Scalar::ONE;
        let b: RP25519 = a.into();
        let d: Fp25519 = a.into();
        let c: RP25519 = RP25519::from(d);
        assert_eq!(b, RP25519(constants::RISTRETTO_BASEPOINT_POINT));
        assert_eq!(c, RP25519(constants::RISTRETTO_BASEPOINT_POINT));
    }

    ///testing simple curve arithmetics to check that `curve25519_dalek` library is used correctly
    #[test]
    fn curve_arithmetics() {
        let mut rng = thread_rng();
        let fp_a = rng.gen::<Fp25519>();
        let fp_b = rng.gen::<Fp25519>();
        let fp_c = fp_a + fp_b;
        let fp_d = RP25519::from(fp_a) + RP25519::from(fp_b);
        assert_eq!(fp_d, RP25519::from(fp_c));
        assert_ne!(fp_d, RP25519(constants::RISTRETTO_BASEPOINT_POINT));
        let fp_e = rng.gen::<Fp25519>();
        let fp_f = rng.gen::<Fp25519>();
        let fp_g = fp_e * fp_f;
        let fp_h = RP25519::from(fp_e) * fp_f;
        assert_eq!(fp_h, RP25519::from(fp_g));
        assert_ne!(fp_h, RP25519(constants::RISTRETTO_BASEPOINT_POINT));
        assert_eq!(RP25519::ZERO, fp_h * Scalar::ZERO.into());
    }

    ///testing curve to unsigned integer conversion has entropy (!= 0)
    #[test]
    fn curve_point_to_hash() {
        let mut rng = thread_rng();
        let fp_a = rng.gen::<RP25519>();
        assert_ne!(0u64, u64::from(fp_a));
        assert_ne!(0u32, u32::from(fp_a));
    }

    #[test]
    #[cfg(debug_assertions)]
    fn non_canonical() {
        use crate::ff::curve_points::NonCanonicalEncoding;

        const ZERO: u128 = 0;
        // 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF is not a valid Ristretto point
        let buf: [u8; 32] = unsafe { std::mem::transmute([!ZERO, !ZERO]) };
        let err = RP25519::deserialize(GenericArray::from_slice(&buf)).unwrap_err();
        assert!(matches!(err, NonCanonicalEncoding(_)));
    }
}
