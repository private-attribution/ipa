use byteorder::{ByteOrder, LittleEndian};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use std::convert::TryFrom;
use std::fmt::{Debug, Display, Error as FmtError, Formatter};
use std::ops::{Add, AddAssign, Sub, SubAssign};

/// An N-bit additive secret share.  N is any number in the range `(0, 128]`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AdditiveShare<const N: u32> {
    v: u128,
}

impl<const N: u32> AdditiveShare<N> {
    fn mask() -> u128 {
        assert!(N > 0);
        assert!(N < 128);
        u128::MAX.wrapping_shr(128 - N)
    }

    #[must_use]
    pub fn share<R>(value: impl Into<u128>, rng: &mut R) -> (Self, Self)
    where
        R: RngCore + CryptoRng,
    {
        let value = value.into();
        let r = u128::from(rng.next_u64()) << 64 | u128::from(rng.next_u64());

        let mut s1 = Self { v: r };
        s1.wrap();
        let s2 = Self { v: value } - r;
        (s1, s2)
    }

    #[must_use]
    pub fn value(self) -> u128 {
        self.v
    }

    fn wrap(&mut self) {
        self.v &= Self::mask();
    }
}

impl<const N: u32> Display for AdditiveShare<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        write!(f, "{}_{}", self.v, N)
    }
}

impl<const N: u32> Debug for AdditiveShare<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        <Self as Display>::fmt(self, f)
    }
}

// Natural implementations of `From` take the size from the type.

impl From<u128> for AdditiveShare<128> {
    fn from(v: u128) -> Self {
        assert_eq!(v, v & Self::mask());
        Self { v }
    }
}

macro_rules! from_smaller {
    ($t:ty, $n:expr) => {
        impl From<$t> for AdditiveShare<$n> {
            fn from(v: $t) -> Self {
                Self { v: u128::from(v) }
            }
        }
    };
}
from_smaller!(u64, 64);
from_smaller!(u32, 32);
from_smaller!(u16, 16);
from_smaller!(u8, 8);

impl<I, const N: u32> Add<I> for AdditiveShare<N>
where
    I: Into<u128>,
{
    type Output = Self;
    fn add(mut self, rhs: I) -> Self::Output {
        self += rhs;
        self
    }
}

impl<I, const N: u32> Sub<I> for AdditiveShare<N>
where
    I: Into<u128>,
{
    type Output = Self;
    fn sub(mut self, rhs: I) -> Self::Output {
        self -= rhs;
        self
    }
}

impl<const N: u32> Add<Self> for AdditiveShare<N> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        self + rhs.v
    }
}

impl<const N: u32> Sub<Self> for AdditiveShare<N> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        self - rhs.v
    }
}

impl<I, const N: u32> AddAssign<I> for AdditiveShare<N>
where
    I: Into<u128>,
{
    fn add_assign(&mut self, rhs: I) {
        self.v = self.v.wrapping_add(rhs.into());
        self.wrap();
    }
}

impl<I, const N: u32> SubAssign<I> for AdditiveShare<N>
where
    I: Into<u128>,
{
    fn sub_assign(&mut self, rhs: I) {
        self.v = self.v.wrapping_sub(rhs.into());
        self.wrap();
    }
}

impl<const N: u32> AddAssign<Self> for AdditiveShare<N> {
    fn add_assign(&mut self, rhs: Self) {
        self.v += rhs.v;
    }
}

impl<const N: u32> SubAssign<Self> for AdditiveShare<N> {
    fn sub_assign(&mut self, rhs: Self) {
        self.v -= rhs.v;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecryptionKey {
    d: Scalar,
}

impl DecryptionKey {
    pub fn new<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        Self {
            d: Scalar::random(rng),
        }
    }

    #[must_use]
    pub fn encryption_key(self) -> EncryptionKey {
        EncryptionKey {
            e: self.d * ED25519_BASEPOINT_POINT,
        }
    }

    #[must_use]
    pub fn decryptor(self, secret: &EncryptedSecret) -> Decryptor {
        let point = secret.secret - self.d * secret.share;
        Decryptor::new(point)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionKey {
    e: EdwardsPoint,
}

impl EncryptionKey {
    #[must_use]
    pub fn encryptor<R>(self, rng: &mut R) -> (Encryptor, EncryptedSecret)
    where
        R: RngCore + CryptoRng,
    {
        let r = Scalar::random(rng);
        let point = Scalar::random(rng) * ED25519_BASEPOINT_POINT;
        let secret = EncryptedSecret {
            share: r * ED25519_BASEPOINT_POINT,
            secret: point + r * self.e,
        };

        (Encryptor::new(point), secret)
    }
}

struct SharedSecret {
    hkdf: Hkdf<Sha256>,
    info: Vec<u8>,
}

impl SharedSecret {
    const INFO_BASE: &'static [u8] = b"SharedSecret";

    fn new(point: EdwardsPoint) -> Self {
        let mut info = Vec::with_capacity(Self::INFO_BASE.len() + 2);
        info.extend_from_slice(Self::INFO_BASE);
        info.push(0); // Byte for holding `n`: the number of bits being extracted.
        info.push(0); // Byte for holding a counter.
        Self {
            hkdf: Hkdf::<Sha256>::new(None, point.compress().as_bytes()),
            info,
        }
    }

    /// Get the next `n`-bit secret derived from the shared secret.
    /// # Panics
    /// If this object is used too many times.  It only supports 255 operations.
    pub fn next(&mut self, n: u32) -> u128 {
        debug_assert!(n > 0 && n <= 128);

        let n = u8::try_from(n).unwrap();
        let n_idx = self.info.len() - 2;
        self.info[n_idx] = n;

        let sz = usize::from((n + 7) / 8); // number of bytes needed
        let mut buf = [0_u8; 16];
        self.hkdf.expand(&self.info, &mut buf[..sz]).unwrap();

        // Increment the counter in place for next time.
        let counter = self.info.last_mut().unwrap();
        *counter = counter.checked_add(1).expect("counter overflow");

        LittleEndian::read_uint128(&buf, sz)
    }
}

pub struct Encryptor {
    ss: SharedSecret,
}

impl Encryptor {
    fn new(point: EdwardsPoint) -> Self {
        Self {
            ss: SharedSecret::new(point),
        }
    }

    pub fn encrypt<const N: u32>(&mut self, share: AdditiveShare<N>) -> AdditiveShare<N> {
        share + self.ss.next(N)
    }
}

pub struct Decryptor {
    ss: SharedSecret,
}

impl Decryptor {
    fn new(point: EdwardsPoint) -> Self {
        Self {
            ss: SharedSecret::new(point),
        }
    }

    pub fn decrypt<const N: u32>(&mut self, share: AdditiveShare<N>) -> AdditiveShare<N> {
        share - self.ss.next(N)
    }
}

#[derive(Debug)]
pub struct EncryptedSecret {
    /// The share of the random value (i.e., `rG`).
    ///
    /// This is rerandomized by generating a new `r'` and adding `r'G`.
    share: EdwardsPoint,
    /// The shared secret.
    ///
    /// This is rerandomized by generating a new `r'` and adding `r'S`.
    secret: EdwardsPoint,
}

impl EncryptedSecret {
    /// Randomize just the share and secret.
    pub fn rerandomize<R>(mut self, e: EncryptionKey, rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let r = Scalar::random(rng);
        self.share += r * ED25519_BASEPOINT_POINT;
        self.secret += r * e.e;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{AdditiveShare, DecryptionKey};
    use rand::{thread_rng, RngCore};

    #[test]
    fn share() {
        let mut rng = thread_rng();
        let v = rng.next_u64();
        let (s1, s2) = AdditiveShare::<64>::share(v, &mut rng);
        assert_eq!(s1 + s2, AdditiveShare::from(v));
    }

    #[test]
    fn rerandomize() {
        let mut rng = thread_rng();
        let v = rng.next_u64();
        let (mut s1, mut s2) = AdditiveShare::<64>::share(v, &mut rng);
        let r = rng.next_u64();
        // Check addition and subtraction.
        assert_eq!((s1 + r) + (s2 - r), AdditiveShare::from(v));
        // Separately with assignment.
        s1 += r;
        s2 -= r;
        assert_eq!(s1 + s2, AdditiveShare::from(v));
    }

    #[test]
    fn encrypt_decrypt() {
        let mut rng = thread_rng();
        let v = rng.next_u64();
        let (s1, s2) = AdditiveShare::<64>::share(v, &mut rng);
        let v = AdditiveShare::from(v);
        assert_ne!(s1, s2);
        assert_ne!(s1, v);
        assert_ne!(s2, v);

        let d = DecryptionKey::new(&mut rng);
        let (mut ex, secret) = d.encryption_key().encryptor(&mut rng);

        // Just encrypt s1 here.
        let c1 = ex.encrypt(s1);
        assert_ne!(c1, s1);

        let mut dx = d.decryptor(&secret);
        let o1 = dx.decrypt(c1);
        assert_eq!(o1, s1);
        assert_eq!(o1 + s2, v);
    }

    #[test]
    fn encrypt_randomize_decrypt() {
        let mut rng = thread_rng();
        let v = rng.next_u64();
        let (s1, s2) = AdditiveShare::<64>::share(v, &mut rng);
        let v = AdditiveShare::from(v);
        assert_ne!(s1, s2);
        assert_ne!(s1, v);
        assert_ne!(s2, v);

        let d = DecryptionKey::new(&mut rng);
        let e = d.encryption_key();
        let (mut e1, secret1) = e.encryptor(&mut rng);
        let (mut e2, secret2) = e.encryptor(&mut rng);

        let mut c1 = e1.encrypt(s1);
        assert_ne!(c1, s1);
        let mut c2 = e2.encrypt(s2);
        assert_ne!(c2, s2);

        // Re-randomize; add r to c1 and subtract r from c2.
        let r = rng.next_u64();
        c1 += r;
        c2 -= r;
        let rs1 = secret1.rerandomize(e, &mut rng);
        let rs2 = secret2.rerandomize(e, &mut rng);

        let mut d1 = d.decryptor(&rs1);
        let mut d2 = d.decryptor(&rs2);
        let o1 = d1.decrypt(c1);
        let o2 = d2.decrypt(c2);
        assert_eq!(o1 + o2, v);
    }

    #[allow(clippy::similar_names)] // Life is too short.
    #[test]
    fn multiple_encryptions() {
        let mut rng = thread_rng();
        let v = rng.next_u64();
        let (s1, s2) = AdditiveShare::<64>::share(v, &mut rng);
        let v = AdditiveShare::from(v);
        assert_ne!(s1, s2);
        assert_ne!(s1, v);
        assert_ne!(s2, v);

        let d = DecryptionKey::new(&mut rng);
        let e = d.encryption_key();
        // We're encrypting twice now...
        let (mut e1a, secret1a) = e.encryptor(&mut rng);
        let (mut e2a, secret2a) = e.encryptor(&mut rng);

        let (mut e1b, secret1b) = e.encryptor(&mut rng);
        let (mut e2b, secret2b) = e.encryptor(&mut rng);

        let mut c1 = e1a.encrypt(s1);
        assert_ne!(c1, s1);
        let mut c2 = e2a.encrypt(s2);
        assert_ne!(c2, s2);

        // Re-randomize; add r to c1 and subtract r from c2.
        let r = rng.next_u64();
        c1 += r;
        c2 -= r;
        // Now rerandomize the shares.
        let rs1a = secret1a.rerandomize(e, &mut rng);
        let rs2a = secret2a.rerandomize(e, &mut rng);

        // And encrypt with the second secret too.
        c1 = e1b.encrypt(c1);
        c2 = e2b.encrypt(c2);

        let mut d1a = d.decryptor(&rs1a);
        let mut d2a = d.decryptor(&rs2a);
        let mut d1b = d.decryptor(&secret1b);
        let mut d2b = d.decryptor(&secret2b);
        let o1 = d1a.decrypt(d1b.decrypt(c1));
        let o2 = d2a.decrypt(d2b.decrypt(c2));
        assert_eq!(o1 + o2, v);
    }
}
