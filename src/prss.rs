use crate::field::Field;
use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes256,
};
use byteorder::{ByteOrder, LittleEndian};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

/// A participant in a 2-of-3 replicated secret sharing.
#[derive(Debug)] // TODO custom debug implementation
pub struct Participant {
    left: Generator,
    left_bits: BitGenerator,
    right: Generator,
    right_bits: BitGenerator,
}

impl Participant {
    /// Generate two random values, one that is known to the left helper
    /// and one that is known to the right helper.
    #[must_use]
    pub fn generate_values(&self, index: u128) -> (u128, u128) {
        (self.left.generate(index), self.right.generate(index))
    }

    /// Generate two random field values, one that is known to the left helper
    /// and one that is known to the right helper.
    #[must_use]
    pub fn generate_fields<F: Field>(&self, index: u128) -> (F, F) {
        let (l, r) = self.generate_values(index);
        (F::from(l), F::from(r))
    }

    /// Generate an additive share of zero.
    /// Each party generates two values, one that is shared with the party to their left,
    /// one with the party to their right.  If all entities add their left share
    /// and subtract their right value, each share will be added once (as a left share)
    /// and subtracted once (as a right share), resulting in values that sum to zero.
    #[must_use]
    pub fn zero_u128(&self, index: u128) -> u128 {
        let (l, r) = self.generate_values(index);
        l.wrapping_sub(r)
    }

    /// Generate an XOR share of zero.
    #[must_use]
    pub fn zero_xor(&self, index: u128) -> u128 {
        let (l, r) = self.generate_values(index);
        l ^ r
    }

    /// Generate an additive shares of a random value.
    /// This is like `zero_u128`, except that the values are added.
    /// The result is that each random value is added twice.  Note that thanks to
    /// using a wrapping add, the result won't be even because the high bit will
    /// wrap around and populate the low bit.
    #[must_use]
    pub fn random_u128(&self, index: u128) -> u128 {
        let (l, r) = self.generate_values(index);
        l.wrapping_add(r)
    }

    /// Generate the next share in `ZZ_2`
    #[must_use]
    pub fn next_zero_bit_share(&mut self) -> bool {
        self.left_bits.next_bit() ^ self.right_bits.next_bit()
    }

    /// Generate additive shares of zero in a field.
    #[must_use]
    pub fn zero<F: Field>(&self, index: u128) -> F {
        let (l, r): (F, F) = self.generate_fields(index);
        l - r
    }

    /// Generate additive shares of a random field value.
    #[must_use]
    pub fn random<F: Field>(&self, index: u128) -> F {
        let (l, r): (F, F) = self.generate_fields(index);
        l + r
    }
}

/// Use this to setup a three-party PRSS configuration.
pub struct ParticipantSetup {
    left: KeyExchange,
    right: KeyExchange,
}

impl ParticipantSetup {
    const CONTEXT_VALUES: &'static [u8] = b"IPA PRSS values";
    const CONTEXT_BITS: &'static [u8] = b"IPA PRSS bits";

    /// Construct a new, unconfigured participant.  This can be configured by
    /// providing public keys for the left and right participants to `setup()`.
    pub fn new<R: RngCore + CryptoRng>(r: &mut R) -> Self {
        Self {
            left: KeyExchange::new(r),
            right: KeyExchange::new(r),
        }
    }

    /// Get the public keys that this setup instance intends to use.
    /// The public key that applies to the left participant is at `.0`,
    /// with the key for the right participant in `.1`.
    #[must_use]
    pub fn public_keys(&self) -> (PublicKey, PublicKey) {
        (self.left.public_key(), self.right.public_key())
    }

    /// Provide the left and right public keys to construct a functioning
    /// participant instance.
    #[must_use]
    pub fn setup(self, left_pk: &PublicKey, right_pk: &PublicKey) -> Participant {
        let fl = self.left.key_exchange(left_pk);
        let fr = self.right.key_exchange(right_pk);
        Participant {
            left: fl.generator(Self::CONTEXT_VALUES),
            left_bits: BitGenerator::from(fl.generator(Self::CONTEXT_BITS)),
            right: fr.generator(Self::CONTEXT_VALUES),
            right_bits: BitGenerator::from(fr.generator(Self::CONTEXT_BITS)),
        }
    }
}

/// The key exchange component of a participant.
pub struct KeyExchange {
    sk: EphemeralSecret,
}

impl KeyExchange {
    pub fn new<R: RngCore + CryptoRng>(r: &mut R) -> Self {
        Self {
            sk: EphemeralSecret::new(r),
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
    #[allow(clippy::missing_panics_doc)] // Panic should be impossible.
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
#[derive(Debug)]
pub struct Generator {
    cipher: Aes256,
}

impl Generator {
    /// Generate the value at the given index.
    #[must_use]
    pub fn generate(&self, index: u128) -> u128 {
        let mut buf = [0_u8; 16];
        LittleEndian::write_u128(&mut buf, index);
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut buf));
        LittleEndian::read_u128(&buf)
    }
}

/// A generator for a single bit.  Unlike the base generator, this is a stateful object.
#[derive(Debug)]
pub struct BitGenerator {
    /// The underlying generator.
    g: Generator,
    /// The current index, shifted left by 7 bits, plus 7 bits that are used
    /// to index into the bits of the u128 the underlying generator creates.
    /// That is, 121 bits of index that are passed to `g` and 7 bits that are
    /// used to select which bit from the output of `g` to return.
    i: u128,
    /// The value we got from the current index (this is outdated if `i & 0x7f == 0`).
    v: u128,
}

impl BitGenerator {
    /// Create a new sequential bit generator starting at the given index.
    /// # Panics
    /// If the index is more than 2^121.  This type shifts the index left and
    /// uses the low bits of that value for a bit index into the `u128` provided
    /// by the underlying `Generator`.
    #[must_use]
    pub fn new(g: Generator, index: u128) -> Self {
        assert!(index.leading_zeros() >= 7, "indices >= 2^121 not supported");
        let i = index << 7;
        Self { g, i, v: 0 }
    }

    #[must_use]
    pub fn next_bit(&mut self) -> bool {
        if self.i.trailing_zeros() >= 7 {
            self.v = self.g.generate(self.i >> 7);
        }
        let v = ((self.v >> (self.i & 0x7f)) & 1) == 1;
        self.i += 1;
        v
    }
}

impl From<Generator> for BitGenerator {
    fn from(g: Generator) -> Self {
        Self { g, i: 0, v: 0 }
    }
}

#[cfg(test)]
pub mod test {
    use aes::{cipher::KeyInit, Aes256};
    use digest::generic_array::GenericArray;
    use rand::thread_rng;

    use crate::field::Fp31;

    use super::{BitGenerator, Generator, KeyExchange, Participant, ParticipantSetup};

    fn make() -> (Generator, Generator) {
        const CONTEXT: &[u8] = b"test generator";
        let mut r = thread_rng();

        let (x1, x2) = (KeyExchange::new(&mut r), KeyExchange::new(&mut r));
        let (pk1, pk2) = (x1.public_key(), x2.public_key());
        let (f1, f2) = (x1.key_exchange(&pk2), x2.key_exchange(&pk1));
        (f1.generator(CONTEXT), f2.generator(CONTEXT))
    }

    /// When inputs are the same, outputs are the same.
    #[test]
    fn generate_equal() {
        let (g1, g2) = make();
        assert_eq!(g1.generate(0), g2.generate(0));
        assert_eq!(g1.generate(1), g2.generate(1));
        assert_eq!(g1.generate(u128::MAX), g2.generate(u128::MAX));

        // Calling g1 twice with the same input produces the same output.
        assert_eq!(g1.generate(12), g1.generate(12));
        // Now that g1 has been invoked more times than g2, we can check
        // that it isn't cheating by using an internal counter.
        assert_eq!(g1.generate(100), g2.generate(100));
        assert_eq!(g2.generate(13), g2.generate(13));
    }

    /// It is *highly* unlikely that two different inputs will produce
    /// equal outputs.
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

    /// The bits produced by a `BitGenerator` aren't all 0 or 1.
    #[test]
    fn bit_non_uniform() {
        let (g1, _g2) = make();
        let mut b1 = BitGenerator::from(g1);
        let (mut all_f, mut all_t) = (true, true);
        for _ in 0..100 {
            let v = b1.next_bit();
            all_f &= !v;
            all_t &= v;
        }
        assert!(!all_f);
        assert!(!all_t);
    }

    /// A bit generator starting at 0 has 128 bit values before it
    /// starts to agree with a generator starting at 1.
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

    /// Creating generators with different contexts means different output.
    #[test]
    fn mismatched_context() {
        let mut r = thread_rng();

        let (e1, e2) = (KeyExchange::new(&mut r), KeyExchange::new(&mut r));
        let (pk1, pk2) = (e1.public_key(), e2.public_key());
        let (f1, f2) = (e1.key_exchange(&pk2), e2.key_exchange(&pk1));
        let (g1, g2) = (f1.generator(b"one"), f2.generator(b"two"));
        assert_ne!(g1.generate(1), g2.generate(1));
    }

    /// Generate three participants.
    /// p1 is left of p2, p2 is left of p3, p3 is left of p1...
    #[must_use]
    pub fn make_three() -> (Participant, Participant, Participant) {
        let mut r = thread_rng();
        let setup1 = ParticipantSetup::new(&mut r);
        let setup2 = ParticipantSetup::new(&mut r);
        let setup3 = ParticipantSetup::new(&mut r);
        let (pk1_l, pk1_r) = setup1.public_keys();
        let (pk2_l, pk2_r) = setup2.public_keys();
        let (pk3_l, pk3_r) = setup3.public_keys();

        let p1 = setup1.setup(&pk3_r, &pk2_l);
        let p2 = setup2.setup(&pk1_r, &pk3_l);
        let p3 = setup3.setup(&pk2_r, &pk1_l);

        (p1, p2, p3)
    }

    #[test]
    fn three_party_values() {
        const IDX: u128 = 7;
        let (p1, p2, p3) = make_three();

        let (r1_l, r1_r) = p1.generate_values(IDX);
        assert_ne!(r1_l, r1_r);
        let (r2_l, r2_r) = p2.generate_values(IDX);
        assert_ne!(r2_l, r2_r);
        let (r3_l, r3_r) = p3.generate_values(IDX);
        assert_ne!(r3_l, r3_r);

        assert_eq!(r1_l, r3_r);
        assert_eq!(r2_l, r1_r);
        assert_eq!(r3_l, r2_r);
    }

    #[test]
    fn three_party_zero_u128() {
        const IDX: u128 = 7;
        let (p1, p2, p3) = make_three();

        let z1 = p1.zero_u128(IDX);
        let z2 = p2.zero_u128(IDX);
        let z3 = p3.zero_u128(IDX);

        assert_eq!(0, z1.wrapping_add(z2).wrapping_add(z3));
    }

    #[test]
    fn three_party_xor_zero() {
        const IDX: u128 = 7;
        let (p1, p2, p3) = make_three();

        let z1 = p1.zero_xor(IDX);
        let z2 = p2.zero_xor(IDX);
        let z3 = p3.zero_xor(IDX);

        assert_eq!(0, z1 ^ z2 ^ z3);
    }

    #[test]
    fn three_party_random_u128() {
        const IDX1: u128 = 7;
        const IDX2: u128 = 21362;
        let (p1, p2, p3) = make_three();

        let r1 = p1.random_u128(IDX1);
        let r2 = p2.random_u128(IDX1);
        let r3 = p3.random_u128(IDX1);

        let v1 = r1.wrapping_add(r2).wrapping_add(r3);
        assert_ne!(0, v1);

        let r1 = p1.random_u128(IDX2);
        let r2 = p2.random_u128(IDX2);
        let r3 = p3.random_u128(IDX2);

        let v2 = r1.wrapping_add(r2).wrapping_add(r3);
        assert_ne!(v1, v2);
    }

    #[test]
    fn three_party_zero_bit() {
        let (mut p1, mut p2, mut p3) = make_three();

        for _ in 0..129 {
            let z1 = p1.next_zero_bit_share();
            let z2 = p2.next_zero_bit_share();
            let z3 = p3.next_zero_bit_share();

            assert!(!(z1 ^ z2 ^ z3));
        }
    }

    #[test]
    fn three_party_fields() {
        const IDX: u128 = 7;
        let (p1, p2, p3) = make_three();

        // These tests do not check that left != right because
        // the field might not be large enough.
        let (r1_l, r1_r): (Fp31, Fp31) = p1.generate_fields(IDX);
        let (r2_l, r2_r) = p2.generate_fields(IDX);
        let (r3_l, r3_r) = p3.generate_fields(IDX);

        assert_eq!(r1_l, r3_r);
        assert_eq!(r2_l, r1_r);
        assert_eq!(r3_l, r2_r);
    }

    #[test]
    fn three_party_zero() {
        const IDX: u128 = 72;
        let (p1, p2, p3) = make_three();

        let z1: Fp31 = p1.zero(IDX);
        let z2 = p2.zero(IDX);
        let z3 = p3.zero(IDX);

        assert_eq!(Fp31::from(0_u8), z1 + z2 + z3);
    }

    #[test]
    fn three_party_random() {
        const IDX1: u128 = 87;
        const IDX2: u128 = 12;
        let (p1, p2, p3) = make_three();

        let r1: Fp31 = p1.random(IDX1);
        let r2 = p2.random(IDX1);
        let r3 = p3.random(IDX1);

        let v1 = r1 + r2 + r3;
        assert_ne!(Fp31::from(0_u8), v1);

        let r1: Fp31 = p1.random(IDX2);
        let r2 = p2.random(IDX2);
        let r3 = p3.random(IDX2);

        let v2 = r1 + r2 + r3;
        assert_ne!(v1, v2);
    }

    #[test]
    #[should_panic]
    fn bad_bit_generator() {
        let g = Generator {
            cipher: Aes256::new(&GenericArray::default()),
        };
        let _ = BitGenerator::new(g, u128::MAX);
    }
}
