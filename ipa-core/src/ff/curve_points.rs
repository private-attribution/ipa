use std::sync::OnceLock;

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    Scalar,
};
use generic_array::GenericArray;
use hkdf::Hkdf;
use sha2::Sha256;
use typenum::{U128, U32};

use crate::{
    ff::{ec_prime_field::Fp25519, Serializable},
    impl_shared_value_common,
    protocol::ipa_prf::PRF_CHUNK,
    secret_sharing::{Block, SharedValue, SharedValueArray, StdArray, Vectorizable},
};

impl Block for CompressedRistretto {
    type Size = U32;
}

impl Block for RistrettoPoint {
    type Size = U128;
}

/// Ristretto point for curve 25519, stored in uncompressed format for efficient
/// additions and multiplications.
///
/// We use Ristretto points such that we have a prime order elliptic curve,
/// This is needed for the Dodis Yampolski PRF.
///
/// decompressing invalid curve points will cause panics,
/// since we always generate curve points from scalars (elements in Fp25519) and
/// only deserialize previously serialized valid points, panics will not occur
/// However, we still added a debug assert to deserialize since values are sent by other servers
///
/// ## Memory/CPU tradeoff
/// We optimize for CPU utilization because invert operations are expensive.
/// Previous implementation used compressed format and we ended up with
/// 10 compress and decompress operations per cycle/row. Storing Ristretto
/// points in uncompressed format allowed us to go down to 3: one in serialize,
/// one in deserialize and one in hash. The only reason why we compress in hash
/// is to get access to raw bytes representation - potentially we could use an
/// API that does not exist in curve25519 crate.
///
/// This tradeoff means that it is highly recommended to avoid collecting
/// many of those points into a vector or any other collection.
/// For PRF evaluation, all of those points
/// are ephemeral (computed once per PRF cycle and then dropped), so this schema
/// works fine as there are only limited number of Ristretto points present
/// in memory at any given time.
///
/// Also, one need to be considerate of stack usage when thinking about vectorizing
/// their operations. Putting too many of those points together may blow up the stack
/// faster. A potential solution would be to keep the compressed view
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RP25519(RistrettoRepr);

impl Default for RP25519 {
    fn default() -> Self {
        Self::ZERO
    }
}

/// Implementing trait for secret sharing
impl SharedValue for RP25519 {
    type Storage = RistrettoPoint;
    const BITS: u32 = 1024;
    const ZERO: Self = Self(RistrettoRepr::Zero);

    impl_shared_value_common!();
}

impl Vectorizable<1> for RP25519 {
    type Array = StdArray<Self, 1>;
}

impl Vectorizable<PRF_CHUNK> for RP25519 {
    type Array = StdArray<Self, PRF_CHUNK>;
}

#[derive(thiserror::Error, Debug)]
#[error("{0:?} is not the canonical encoding of a Ristretto point.")]
pub struct NonCanonicalEncoding(CompressedRistretto);

impl Serializable for RP25519 {
    type Size = <CompressedRistretto as Block>::Size;
    type DeserializationError = NonCanonicalEncoding;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        *buf.as_mut() = self.0.as_point().compress().to_bytes();
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserializationError> {
        let point = CompressedRistretto((*buf).into());
        let point = point.decompress().ok_or(NonCanonicalEncoding(point))?;
        Ok(Self::from(point))
    }
}

impl std::ops::Add for RP25519 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self((self.0.as_point() + rhs.0.as_point()).into())
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
        Self(self.0.as_point().neg().into())
    }
}

impl std::ops::Sub for RP25519 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self((self.0.as_point() - rhs.0.as_point()).into())
    }
}

impl std::ops::SubAssign for RP25519 {
    #[allow(clippy::assign_op_pattern)]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

/// Scalar Multiplication
/// allows to multiply curve points with scalars from Fp25519
impl std::ops::Mul<Fp25519> for RP25519 {
    type Output = Self;

    fn mul(self, rhs: Fp25519) -> Self {
        Self((self.0.as_point() * Scalar::from(rhs)).into())
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
        Self::from(Fp25519::from(s))
    }
}

impl From<Fp25519> for RP25519 {
    fn from(s: Fp25519) -> Self {
        Self((RistrettoPoint::mul_base(&s.into())).into())
    }
}

impl From<RistrettoPoint> for RP25519 {
    fn from(s: RistrettoPoint) -> Self {
        Self(RistrettoRepr::Point(s))
    }
}

/// This function allows converting curve points into unsigned 8-byte integers in batch.
/// It provides better performance as the cost of invert is amortized.
///
/// This functionality is based on the assumption that if any Ristretto point `P` provides
/// sufficient entropy to generate a uniformly random 64 bit value, then `2*P` does the same.
///
/// ## Panics
/// If size of the input iterator is greater than `N`.
pub fn batch_convert<const N: usize, I: Iterator<Item = RP25519>>(input: I) -> [u64; N]
where
    RP25519: Vectorizable<N>,
{
    let points = input.collect::<<RP25519 as Vectorizable<N>>::Array>();
    let compressed: [_; N] =
        RistrettoPoint::double_and_compress_batch(points.iter().map(|p| p.0.as_point()))
            .try_into()
            .unwrap();

    compressed.map(|compressed_point| {
        let hk = extract(compressed_point);
        let mut okm = [0u8; 8];
        hk.expand(&[], &mut okm).unwrap();

        u64::from_le_bytes(okm)
    })
}

fn extract(point: CompressedRistretto) -> Hkdf<Sha256> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    Hkdf::<Sha256>::new(None, point.as_bytes())
}

///allows to convert curve points into unsigned integers, preserving high entropy
macro_rules! cp_hash_impl {
    ($u_type:ty) => {
        impl From<RP25519> for $u_type {
            fn from(s: RP25519) -> Self {
                use crate::ff::curve_points::extract;

                // make the behavior of this function consistent with batch_compress
                // by multiplying the Ristretto point by a factor of two.
                let two = Scalar::from(2_u64);

                let hk = extract((two * s.0.as_point()).compress());
                let mut okm = <$u_type>::MIN.to_le_bytes();
                //error invalid length from expand only happens when okm is very large
                hk.expand(&[], &mut okm).unwrap();
                <$u_type>::from_le_bytes(okm)
            }
        }
    };
}

cp_hash_impl!(u64);

/// implementing random curve point generation for testing purposes,
/// in the actual IPA protocol, we generate them from scalars, i.e. Fp25519
#[cfg(test)]
impl rand::distributions::Distribution<RP25519> for rand::distributions::Standard {
    fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> RP25519 {
        let mut scalar_bytes = [0u8; 64];
        rng.fill_bytes(&mut scalar_bytes);
        RP25519(RistrettoPoint::from_uniform_bytes(&scalar_bytes).into())
    }
}

/// Internal representation of Ristretto point, suitable
/// for our needs.
/// Due to constraints imposed by dalek crate,
/// we can't construct a zero uncompressed Ristretto point
/// at compile time. It is only possible to construct
/// a compressed ristretto from 0 byte array in const context.
/// We work around that limitation by adding an enum value
/// that represents a zero value.
#[derive(Clone, Copy, Eq, Debug)]
enum RistrettoRepr {
    /// In PRF code this path is never used as
    /// we always construct Ristretto points from scalars
    Zero,
    Point(RistrettoPoint),
}

impl PartialEq for RistrettoRepr {
    fn eq(&self, other: &Self) -> bool {
        self.as_point().eq(other.as_point())
    }
}

impl RistrettoRepr {
    #[inline]
    fn zero() -> &'static RistrettoPoint {
        static INSTANCE: OnceLock<RistrettoPoint> = OnceLock::new();
        INSTANCE.get_or_init(|| {
            let zero = CompressedRistretto([0_u8; 32]);
            // we could also cache the compressed Ristretto, if we end up
            // sending a lot of zeroes
            zero.decompress().unwrap()
        })
    }

    pub fn as_point(&self) -> &RistrettoPoint {
        match self {
            Self::Zero => Self::zero(),
            Self::Point(p) => p,
        }
    }
}

impl From<RistrettoPoint> for RistrettoRepr {
    fn from(value: RistrettoPoint) -> Self {
        Self::Point(value)
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use std::array;

    use curve25519_dalek::{constants, scalar::Scalar};
    use generic_array::GenericArray;
    use rand::{rngs::StdRng, thread_rng, Rng};
    use rand_core::SeedableRng;
    use typenum::U32;

    use crate::{
        ff::{
            curve_points::{batch_convert, RP25519},
            ec_prime_field::Fp25519,
            Serializable,
        },
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
        assert_eq!(b, RP25519::from(constants::RISTRETTO_BASEPOINT_POINT));
        assert_eq!(c, RP25519::from(constants::RISTRETTO_BASEPOINT_POINT));
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
        assert_ne!(fp_d, RP25519::from(constants::RISTRETTO_BASEPOINT_POINT));
        let fp_e = rng.gen::<Fp25519>();
        let fp_f = rng.gen::<Fp25519>();
        let fp_g = fp_e * fp_f;
        let fp_h = RP25519::from(fp_e) * fp_f;
        assert_eq!(fp_h, RP25519::from(fp_g));
        assert_ne!(fp_h, RP25519::from(constants::RISTRETTO_BASEPOINT_POINT));
        assert_eq!(RP25519::ZERO, fp_h * Scalar::ZERO.into());
        assert_eq!(fp_h, fp_h + RP25519::ZERO);
    }

    /// testing curve to unsigned integer conversion has entropy (!= 0)
    #[test]
    fn curve_point_to_hash() {
        let mut rng = thread_rng();
        let fp_a = rng.gen::<RP25519>();
        assert_ne!(0u64, u64::from(fp_a));
        assert_ne!(0u32, u32::from(fp_a));

        assert_ne!(
            batch_convert::<16, _>(
                array::from_fn::<_, 16, _>(|_| rng.gen::<RP25519>()).into_iter()
            ),
            array::from_fn(|_| 0u64)
        );
    }

    #[test]
    fn batch_convert_matches_hash() {
        let seed = thread_rng().gen();
        let mut rng = StdRng::seed_from_u64(seed);
        println!("seed = {seed}");
        let input: [RP25519; 16] = array::from_fn(|_| rng.gen());
        let a = batch_convert::<16, _>(input.into_iter());
        let b = input.map(u64::from);

        assert_eq!(a, b);
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
