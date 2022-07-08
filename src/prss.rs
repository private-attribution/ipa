use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes256,
};
use byteorder::{ByteOrder, NativeEndian};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub struct Endpoint {
    left: Generator,
    left_bits: BitGenerator,
    right: Generator,
    right_bits: BitGenerator,
}

impl Endpoint {
    /// Generate additive shares of zero.
    /// TODO: generate these in the appropriate field rather than `ZZ_{2^128}`.
    #[must_use]
    pub fn zero_value_share(&self, index: u128) -> u128 {
        self.left
            .generate(index)
            .wrapping_sub(self.right.generate(index))
    }

    /// Generate the next share in `ZZ_2`
    #[must_use]
    pub fn next_zero_bit_share(&mut self) -> bool {
        self.left_bits.next_bit() ^ self.right_bits.next_bit()
    }
}

/// Use this to setup a three-party PRSS configuration.
pub struct EndpointSetup {
    left: KeyExchange,
    right: KeyExchange,
}

impl EndpointSetup {
    const CONTEXT_VALUES: &'static [u8] = b"IPA PRSS values";
    const CONTEXT_BITS: &'static [u8] = b"IPA PRSS bits";

    pub fn new<R: RngCore + CryptoRng>(r: &mut R) -> Self {
        Self {
            left: KeyExchange::new(r),
            right: KeyExchange::new(r),
        }
    }

    #[must_use]
    pub fn setup(self, left_pk: &PublicKey, right_pk: &PublicKey) -> Endpoint {
        let fl = self.left.key_exchange(left_pk);
        let fr = self.right.key_exchange(right_pk);
        Endpoint {
            left: fl.generator(Self::CONTEXT_VALUES),
            left_bits: BitGenerator::from(fl.generator(Self::CONTEXT_BITS)),
            right: fr.generator(Self::CONTEXT_VALUES),
            right_bits: BitGenerator::from(fr.generator(Self::CONTEXT_BITS)),
        }
    }
}

pub struct KeyExchange {
    sk: EphemeralSecret,
}

impl KeyExchange {
    pub fn new<R: RngCore + CryptoRng>(r: &mut R) -> Self {
        let mut r = rng::Adapter::from(r);
        Self {
            sk: EphemeralSecret::new(&mut r),
        }
    }

    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.sk)
    }

    #[must_use]
    pub fn key_exchange(self, pk: &PublicKey) -> GeneratorFactory {
        debug_assert_ne!(pk, &self.public_key(), "self key exchange detected");
        let secret = self.sk.diffie_hellman(pk);
        let kdf = Hkdf::<Sha256>::new(None, secret.as_bytes());
        GeneratorFactory { kdf }
    }
}

/// This intermediate object exists so that multiple generators can be constructed,
/// with each one dedicated to one purpose.
pub struct GeneratorFactory {
    kdf: Hkdf<Sha256>,
}

impl GeneratorFactory {
    /// Create a new generator using the provided context string.
    /// # Panics
    /// Never: we don't let that happen.
    #[must_use]
    pub fn generator(&self, context: &[u8]) -> Generator {
        let mut k = GenericArray::default();
        self.kdf.expand(context, &mut k).unwrap();
        Generator {
            cipher: Aes256::new(&k),
        }
    }
}

/// The basic generator.  This generates values based on an arbitrary index.
pub struct Generator {
    cipher: Aes256,
}

impl Generator {
    /// Generate the value at the given index.
    #[must_use]
    pub fn generate(&self, index: u128) -> u128 {
        let mut buf = [0_u8; 16];
        NativeEndian::write_u128(&mut buf, index);
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut buf));
        NativeEndian::read_u128(&buf)
    }
}

/// A generator for a single bit.  Unlike the base generator, this is a stateful object.
pub struct BitGenerator {
    /// The underlying generator.
    g: Generator,
    /// The current index, shifted left by 7 bits, plus a 7 bit index.
    i: u128,
    /// The value we got from the current index (this is outdated if `i & 0x7f == 0`).
    v: u128,
}

impl BitGenerator {
    #[must_use]
    pub fn new(g: Generator, i: u128) -> Self {
        let i = i.checked_shl(7).expect("Index needs to be less than 2^121");
        Self { g, i, v: 0 }
    }

    #[must_use]
    pub fn next_bit(&mut self) -> bool {
        if self.i.trailing_zeros() >= 7 {
            self.v = self.g.generate(self.i >> 7);
        }
        let v = (self.v >> (self.i & 0x7f)) & 1 == 1;
        self.i += 1;
        v
    }
}

impl From<Generator> for BitGenerator {
    fn from(g: Generator) -> Self {
        Self { g, i: 0, v: 0 }
    }
}

// x25519-dalek uses an old version of the rand_core crate.
// This is incompatible with the rand crate that the rest of the project uses,
// but it is basically the same.  This adapter manages that.
mod rng {
    use old_rand_core::{CryptoRng as OldCryptoRng, Error as OldError, RngCore as OldRngCore};
    use rand_core::{CryptoRng, RngCore};

    pub struct Adapter<'a, R>(&'a mut R);

    impl<'a, R: RngCore + CryptoRng> From<&'a mut R> for Adapter<'a, R> {
        fn from(r: &'a mut R) -> Self {
            Self(r)
        }
    }

    impl<R: RngCore> OldRngCore for Adapter<'_, R> {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.fill_bytes(dest);
        }
        fn next_u32(&mut self) -> u32 {
            self.0.next_u32()
        }
        fn next_u64(&mut self) -> u64 {
            self.0.next_u64()
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), OldError> {
            self.0.try_fill_bytes(dest).map_err(OldError::new)
        }
    }

    impl<R: CryptoRng> OldCryptoRng for Adapter<'_, R> {}
}

#[cfg(test)]
mod test {
    use rand::thread_rng;

    use super::{BitGenerator, Generator, KeyExchange};

    fn make() -> (Generator, Generator) {
        const CONTEXT: &[u8] = b"test generator";
        let mut r = thread_rng();

        let (ke1, ke2) = (KeyExchange::new(&mut r), KeyExchange::new(&mut r));
        let (pk1, pk2) = (ke1.public_key(), ke2.public_key());
        let (f1, f2) = (ke1.key_exchange(&pk2), ke2.key_exchange(&pk1));
        (f1.generator(CONTEXT), f2.generator(CONTEXT))
    }

    #[test]
    fn generate_equal() {
        let (g1, g2) = make();
        assert_eq!(g1.generate(0), g2.generate(0));
        assert_eq!(g1.generate(1), g2.generate(1));
        assert_eq!(g1.generate(u128::MAX), g2.generate(u128::MAX));

        assert_eq!(g1.generate(12), g1.generate(12), "g1 -> g1");
        assert_eq!(
            g1.generate(100),
            g2.generate(100),
            "not just using an internal counter"
        );
        assert_eq!(g2.generate(13), g2.generate(13), "g2 -> g2");
    }

    #[test]
    fn generate_unlikely() {
        let (g1, g2) = make();
        // An equal output is *unlikely*.
        assert_ne!(g1.generate(0), g2.generate(1));
        // As is a zero output.
        assert_ne!(0, g1.generate(0));
    }

    #[test]
    fn bit_generator() {
        let (g1, g2) = make();
        let (mut b1, mut b2) = (BitGenerator::from(g1), BitGenerator::from(g2));

        // Get a few values out and test all the bits.
        for _ in 0..257 {
            assert_eq!(b1.next_bit(), b2.next_bit());
        }
    }

    #[test]
    fn bit_non_uniform() {
        let (g1, _g2) = make();
        let mut b1 = BitGenerator::from(g1);
        let (mut all_f, mut all_t) = (true, true);
        for _ in 0..128 {
            let v = b1.next_bit();
            all_f &= !v;
            all_t &= v;
        }
        assert!(!all_f);
        assert!(!all_t);
    }

    #[test]
    fn offset_bit_generator() {
        let (g1, g2) = make();
        let mut b1 = BitGenerator::from(g1);
        // Consume the first block of bits.
        for _ in 0..128 {
            let _ = b1.next_bit();
        }

        let mut b2 = BitGenerator::new(g2, 1);
        for _ in 0..129 {
            assert_eq!(b1.next_bit(), b2.next_bit());
        }
    }

    #[test]
    fn mismatched_context() {
        let mut r = thread_rng();

        let (e1, e2) = (KeyExchange::new(&mut r), KeyExchange::new(&mut r));
        let (pk1, pk2) = (e1.public_key(), e2.public_key());
        let (f1, f2) = (e1.key_exchange(&pk2), e2.key_exchange(&pk1));
        let (g1, g2) = (f1.generator(b"one"), f2.generator(b"two"));
        assert_ne!(g1.generate(1), g2.generate(1));
    }
}
