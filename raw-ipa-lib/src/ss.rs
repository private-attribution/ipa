use byteorder::{ByteOrder, LittleEndian};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use std::convert::TryFrom;
use std::fmt::{Debug, Display, Error as FmtError, Formatter};
use std::ops::{Add, AddAssign, BitXor, BitXorAssign, Sub, SubAssign};

/// An N-bit additive secret share.  N is any number in the range `(0, 128]`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AdditiveShare<const N: u32> {
    v: u128,
}

impl<const N: u32> AdditiveShare<N> {
    #[must_use]
    pub fn share<R>(value: impl Into<u128>, rng: &mut R) -> (Self, Self)
    where
        R: RngCore + CryptoRng,
    {
        let value = value.into();
        let r = u128::from(rng.next_u64()) << 64 | u128::from(rng.next_u64());
        (Self::new(r), Self::new(value) - r)
    }

    fn mask(&mut self) {
        self.v &= <Self as BitWidth<N>>::mask();
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

impl<const N: u32> From<AdditiveShare<N>> for u128 {
    fn from(v: AdditiveShare<N>) -> Self {
        v.v
    }
}

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

impl<I, const N: u32> AddAssign<I> for AdditiveShare<N>
where
    I: Into<u128>,
{
    fn add_assign(&mut self, rhs: I) {
        self.v = self.v.wrapping_add(rhs.into());
        self.mask();
    }
}

impl<I, const N: u32> SubAssign<I> for AdditiveShare<N>
where
    I: Into<u128>,
{
    fn sub_assign(&mut self, rhs: I) {
        self.v = self.v.wrapping_sub(rhs.into());
        self.mask();
    }
}

/// An N-bit additive secret share.  N is any number in the range `(0, 128]`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct XorShare<const N: u32> {
    v: u128,
}

impl<const N: u32> XorShare<N> {
    #[must_use]
    pub fn share<R>(value: impl Into<u128>, rng: &mut R) -> (Self, Self)
    where
        R: RngCore + CryptoRng,
    {
        let value = value.into();
        let r = u128::from(rng.next_u64()) << 64 | u128::from(rng.next_u64());
        (Self::new(r), Self::new(value) ^ r)
    }

    fn mask(&mut self) {
        self.v &= <Self as BitWidth<N>>::mask();
    }
}

impl<const N: u32> Display for XorShare<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        write!(f, "{}_{}", self.v, N)
    }
}

impl<const N: u32> Debug for XorShare<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        <Self as Display>::fmt(self, f)
    }
}

impl<const N: u32> From<XorShare<N>> for u128 {
    fn from(v: XorShare<N>) -> Self {
        v.v
    }
}

impl<I, const N: u32> BitXor<I> for XorShare<N>
where
    I: Into<u128>,
{
    type Output = Self;
    fn bitxor(mut self, rhs: I) -> Self::Output {
        self ^= rhs;
        self
    }
}

impl<I, const N: u32> BitXorAssign<I> for XorShare<N>
where
    I: Into<u128>,
{
    fn bitxor_assign(&mut self, rhs: I) {
        self.v ^= rhs.into();
        self.mask();
    }
}

/// Marker trait for shares of a certain width.
pub trait BitWidth<const N: u32> {
    fn new(v: u128) -> Self;

    #[must_use]
    fn mask() -> u128 {
        assert!(N > 0);
        assert!(N < 128);
        u128::MAX.wrapping_shr(128 - N)
    }
}
impl<const N: u32> BitWidth<N> for AdditiveShare<N> {
    fn new(v: u128) -> Self {
        let mut s = Self { v };
        s.mask();
        s
    }
}

impl<const N: u32> BitWidth<N> for XorShare<N> {
    fn new(v: u128) -> Self {
        let mut s = Self { v };
        s.mask();
        s
    }
}

impl<const N: u32> TryFrom<u128> for AdditiveShare<N> {
    type Error = ();
    fn try_from(v: u128) -> Result<Self, Self::Error> {
        if v & <Self as BitWidth<N>>::mask() == v {
            Ok(Self::new(v))
        } else {
            Err(())
        }
    }
}

impl<const N: u32> TryFrom<u128> for XorShare<N> {
    type Error = ();
    fn try_from(v: u128) -> Result<Self, Self::Error> {
        if v & <Self as BitWidth<N>>::mask() == v {
            Ok(Self::new(v))
        } else {
            Err(())
        }
    }
}

pub trait EncryptSelf<U> {
    /// Encrypt value using entropy, `e`.
    fn encrypt(self, e: U) -> Self;
}

impl<const N: u32> EncryptSelf<u128> for AdditiveShare<N> {
    fn encrypt(self, e: u128) -> Self {
        self + e
    }
}

impl<const N: u32> EncryptSelf<u128> for XorShare<N> {
    fn encrypt(self, e: u128) -> Self {
        self ^ e
    }
}

pub trait DecryptSelf<U> {
    /// Decrypt this value using entropy, `e`.
    fn decrypt(self, e: U) -> Self;
}

impl<const N: u32> DecryptSelf<u128> for AdditiveShare<N> {
    fn decrypt(self, e: u128) -> Self {
        self - e
    }
}

impl<const N: u32> DecryptSelf<u128> for XorShare<N> {
    fn decrypt(self, e: u128) -> Self {
        self ^ e
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

    /// Given an `EncryptedSecret` produce a `Decryptor`.
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
    /// Get an `Encryptor` based on this encryption key.  This also returns
    /// an `EncryptedSecret`. If you have the `EncryptedSecret` and the
    /// `DecryptionKey` that correspond to this `EncryptionKey`, you can use
    /// those to produce a `Decryptor`.
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

/// Shared implementation of `Encryptor` and `Decryptor`.
/// This is able to produce multiple derived secrets from a shared secret.
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
    #[must_use]
    fn next(&mut self, n: u32) -> u128 {
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

/// An encryptor of shares.  This is a stateful object.  Each time it decrypts, it changes state.
pub struct Encryptor {
    ss: SharedSecret,
}

impl Encryptor {
    fn new(point: EdwardsPoint) -> Self {
        Self {
            ss: SharedSecret::new(point),
        }
    }

    pub fn encrypt<T: EncryptSelf<u128> + BitWidth<N>, const N: u32>(&mut self, share: T) -> T {
        share.encrypt(self.ss.next(N))
    }
}

/// A decryptor of shares.  This is a stateful object.  Each time it decrypts, it changes state.
pub struct Decryptor {
    ss: SharedSecret,
}

impl Decryptor {
    fn new(point: EdwardsPoint) -> Self {
        Self {
            ss: SharedSecret::new(point),
        }
    }

    pub fn decrypt<T: DecryptSelf<u128> + BitWidth<N>, const N: u32>(&mut self, share: T) -> T {
        share.decrypt(self.ss.next(N))
    }
}

#[derive(Debug)]
pub struct EncryptedSecret {
    /// The share of the random value (i.e., `rG`).
    ///
    /// This is rerandomized by generating a new `r'` and adding `r'G`.
    share: EdwardsPoint,
    /// The shared secret, encrypted with `E` (i.e., `S + rE`).
    ///
    /// This is rerandomized by generating a new `r'` and adding `r'E`.
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
    use super::{AdditiveShare, BitWidth, DecryptionKey, XorShare};
    use rand::{thread_rng, RngCore};

    fn from64<T>(v: u64) -> T
    where
        T: BitWidth<64> + TryFrom<u128, Error = ()>,
    {
        T::try_from(u128::from(v)).unwrap()
    }

    #[test]
    fn share() {
        let mut rng = thread_rng();
        let v = rng.next_u64();
        let (s1, s2) = AdditiveShare::<64>::share(v, &mut rng);
        assert_eq!(s1 + s2, from64(v));
    }

    #[test]
    fn share_xor() {
        let mut rng = thread_rng();
        let v = rng.next_u64();
        let (s1, s2) = XorShare::<64>::share(v, &mut rng);
        assert_eq!(s1 ^ s2, from64(v));
    }

    #[test]
    fn rerandomize() {
        let mut rng = thread_rng();
        let v = rng.next_u64();
        let (mut s1, mut s2) = AdditiveShare::<64>::share(v, &mut rng);
        let r = rng.next_u64();
        // Check addition and subtraction.
        assert_eq!((s1 + r) + (s2 - r), from64(v));
        // Separately with assignment.
        s1 += r;
        s2 -= r;
        assert_eq!(s1 + s2, from64(v));
    }

    #[test]
    fn rerandomize_xor() {
        let mut rng = thread_rng();
        let v = rng.next_u64();
        let (mut s1, mut s2) = XorShare::<64>::share(v, &mut rng);
        let r = rng.next_u64();
        // Check addition and subtraction.
        assert_eq!((s1 ^ r) ^ (s2 ^ r), from64(v));
        // Separately with assignment.
        s1 ^= r;
        s2 ^= r;
        assert_eq!(s1 ^ s2, from64(v));
    }

    #[test]
    fn encrypt_decrypt() {
        let mut rng = thread_rng();
        let v = rng.next_u64();
        let (s1, s2) = AdditiveShare::<64>::share(v, &mut rng);
        let v = from64(v);
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
    fn encrypt_decrypt_xor() {
        let mut rng = thread_rng();
        let v = rng.next_u64();
        let (s1, s2) = XorShare::<64>::share(v, &mut rng);
        let v = from64(v);
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
        assert_eq!(o1 ^ s2, v);
    }

    #[test]
    fn encrypt_randomize_decrypt() {
        let mut rng = thread_rng();
        let v = rng.next_u64();
        let (s1, s2) = AdditiveShare::<64>::share(v, &mut rng);
        let v = from64(v);
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
        let v = from64(v);
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

        let c1a = e1a.encrypt(s1);
        assert_ne!(c1a, s1);
        let c2a = e2a.encrypt(s2);
        assert_ne!(c2a, s2);

        // Re-randomize; add r to c1 and subtract r from c2.
        let r = rng.next_u64();
        let c1r = c1a + r;
        let c2r = c2a - r;
        // Now rerandomize the shares.
        let rs1a = secret1a.rerandomize(e, &mut rng);
        let rs2a = secret2a.rerandomize(e, &mut rng);

        // And encrypt with the second secret too.
        let c1b = e1b.encrypt(c1r);
        assert_ne!(c1b, c1r);
        let c2b = e2b.encrypt(c2r);
        assert_ne!(c2b, c2r);

        let mut d1a = d.decryptor(&rs1a);
        let mut d2a = d.decryptor(&rs2a);
        let mut d1b = d.decryptor(&secret1b);
        let mut d2b = d.decryptor(&secret2b);
        let o1 = d1a.decrypt(d1b.decrypt(c1b));
        let o2 = d2a.decrypt(d2b.decrypt(c2b));
        assert_eq!(o1 + o2, v);
    }
}
