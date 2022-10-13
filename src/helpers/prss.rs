use crate::field::Field;
use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes256,
};
use byteorder::{ByteOrder, LittleEndian};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use std::fmt::{Debug, Formatter};
use std::ops::Index;
use std::{marker::PhantomData, mem::size_of};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub trait SpaceIndex: Copy {
    const MAX: usize;

    #[must_use]
    fn as_usize(&self) -> usize;

    #[must_use]
    fn to_bytes(&self) -> [u8; 8] {
        let mut buf = [0; 8];
        for (i, &v) in self.as_usize().to_le_bytes().iter().enumerate() {
            buf[i] = v;
        }
        buf
    }
}

/// A participant in a 2-of-N replicated secret sharing.
#[derive(Debug)] // TODO custom debug implementation
#[allow(clippy::module_name_repetitions)]
pub struct PrssSpace {
    left: Generator,
    right: Generator,
}

impl PartialEq for PrssSpace {
    fn eq(&self, other: &Self) -> bool {
        self.generate_values(1) == other.generate_values(1)
    }
}

impl PrssSpace {
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

    /// Turn this space into a pair of random number generators, one that is shared
    /// with the left and one that is shared with the right.
    /// Nothing prevents this from being used after calls to generate values,
    /// but it should not be used in both ways.
    #[must_use]
    pub fn as_rngs(&self) -> (PrssRng, PrssRng) {
        (
            PrssRng {
                generator: self.left.clone(),
                counter: 0,
            },
            PrssRng {
                generator: self.right.clone(),
                counter: 0,
            },
        )
    }
}

/// An implementation of `RngCore` that uses the same underlying `Generator`.
/// For use in place of `PrssSpace` where indexing cannot be used, such as
/// in APIs that expect `Rng`.
#[allow(clippy::module_name_repetitions)]
pub struct PrssRng {
    generator: Generator,
    counter: u128,
}

impl RngCore for PrssRng {
    #[allow(clippy::cast_possible_truncation)]
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    // This implementation wastes half of the bits that are generated.
    // That is OK for the same reason that we use in converting a `u128` to a small `Field`.
    #[allow(clippy::cast_possible_truncation)]
    fn next_u64(&mut self) -> u64 {
        let v = self.generator.generate(self.counter);
        self.counter += 1;
        v as u64
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::impls::fill_bytes_via_next(self, dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        rand_core::impls::fill_bytes_via_next(self, dest);
        Ok(())
    }
}

impl CryptoRng for PrssRng {}

/// A single participant in the protocol.
/// This holds multiple streams of correlated (pseudo)randomness, indexed by `I`.
pub struct Participant<I: SpaceIndex> {
    // This would be `[PrssSpace; I::MAX]` with `feature(generic_const_exprs)`,
    // but that is still in Nightly.
    spaces: Vec<PrssSpace>,
    _marker: PhantomData<I>,
}

impl<I: SpaceIndex> Debug for Participant<I> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Participant[0..{0}]", I::MAX)
    }
}

impl<I: SpaceIndex> Index<I> for Participant<I> {
    type Output = PrssSpace;
    fn index(&self, idx: I) -> &Self::Output {
        &self.spaces[idx.as_usize()]
    }
}

/// Use this to setup a three-party PRSS configuration.
pub struct ParticipantSetup {
    left: KeyExchange,
    right: KeyExchange,
}

impl ParticipantSetup {
    const CONTEXT_BASE: &'static [u8] = b"IPA PRSS ";

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
    /// This is generic over `SpaceIndex` so that it can construct the
    /// appropriate number of spaces for use by a protocol participant.
    #[must_use]
    pub fn setup<I: SpaceIndex>(self, left_pk: &PublicKey, right_pk: &PublicKey) -> Participant<I> {
        let fl = self.left.key_exchange(left_pk);
        let fr = self.right.key_exchange(right_pk);
        let mut context = Vec::with_capacity(Self::CONTEXT_BASE.len() + size_of::<usize>());
        context.extend_from_slice(Self::CONTEXT_BASE);
        let spaces = (0..I::MAX)
            .map(|i| {
                context.truncate(Self::CONTEXT_BASE.len());
                context.extend_from_slice(&i.to_le_bytes());
                PrssSpace {
                    left: fl.generator(&context),
                    right: fr.generator(&context),
                }
            })
            .collect();

        Participant {
            spaces,
            _marker: PhantomData::default(),
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
#[derive(Debug, Clone)]
pub struct Generator {
    cipher: Aes256,
}

impl Generator {
    /// Generate the value at the given index.
    /// This uses the MMO^{\pi} function described in <https://eprint.iacr.org/2019/074>.
    #[must_use]
    pub fn generate(&self, index: u128) -> u128 {
        let mut buf = [0_u8; 16];
        LittleEndian::write_u128(&mut buf, index);
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut buf));
        LittleEndian::read_u128(&buf) ^ index
    }
}

#[cfg(test)]
pub mod test {
    use rand::{thread_rng, Rng};

    use crate::protocol::QueryId;
    use crate::test_fixture::{make_participants, TestWorld};
    use crate::{
        field::Fp31,
        test_fixture::{make_contexts, make_world, TestStep},
    };

    use super::{Generator, KeyExchange, Participant, PrssRng, PrssSpace, SpaceIndex};

    /// In testing, having a single space is easiest to use.
    /// This provides an implementation of `PrssSpace`.
    #[derive(Clone, Copy)]
    pub struct SingleSpace;

    impl SpaceIndex for SingleSpace {
        const MAX: usize = 1;
        fn as_usize(&self) -> usize {
            0
        }
    }

    // This makes it easier to use the single space.
    impl std::ops::Deref for Participant<SingleSpace> {
        type Target = PrssSpace;
        fn deref(&self) -> &Self::Target {
            &self[SingleSpace]
        }
    }

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

    #[test]
    fn three_party_values() {
        const IDX: u128 = 7;
        let (p1, p2, p3) = make_participants();

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
        let (p1, p2, p3) = make_participants();

        let z1 = p1.zero_u128(IDX);
        let z2 = p2.zero_u128(IDX);
        let z3 = p3.zero_u128(IDX);

        assert_eq!(0, z1.wrapping_add(z2).wrapping_add(z3));
    }

    #[test]
    fn three_party_xor_zero() {
        const IDX: u128 = 7;
        let (p1, p2, p3) = make_participants();

        let z1 = p1.zero_xor(IDX);
        let z2 = p2.zero_xor(IDX);
        let z3 = p3.zero_xor(IDX);

        assert_eq!(0, z1 ^ z2 ^ z3);
    }

    #[test]
    fn three_party_random_u128() {
        const IDX1: u128 = 7;
        const IDX2: u128 = 21362;
        let (p1, p2, p3) = make_participants();

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
    fn three_party_fields() {
        const IDX: u128 = 7;
        let (p1, p2, p3) = make_participants();

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
        let (p1, p2, p3) = make_participants();

        let z1: Fp31 = p1.zero(IDX);
        let z2 = p2.zero(IDX);
        let z3 = p3.zero(IDX);

        assert_eq!(Fp31::from(0_u8), z1 + z2 + z3);
    }

    #[test]
    fn three_party_random() {
        const IDX1: u128 = 74;
        const IDX2: u128 = 12634;
        let (p1, p2, p3) = make_participants();

        let r1: Fp31 = p1.random(IDX1);
        let r2 = p2.random(IDX1);
        let r3 = p3.random(IDX1);
        let v1 = r1 + r2 + r3;

        // There isn't enough entropy in this field (~5 bits) to be sure that the test will pass.
        // So run a few rounds (~21 -> ~100 bits) looking for a mismatch.
        let mut v2 = Fp31::from(0_u8);
        for i in IDX2..(IDX2 + 21) {
            let r1: Fp31 = p1.random(i);
            let r2 = p2.random(i);
            let r3 = p3.random(i);

            v2 = r1 + r2 + r3;
            if v1 != v2 {
                break;
            }
        }
        assert_ne!(v1, v2);
    }

    #[test]
    fn prss_rng() {
        fn same_rng(mut a: PrssRng, mut b: PrssRng) {
            assert_eq!(a.gen::<u32>(), b.gen::<u32>());
            assert_eq!(a.gen::<[u8; 20]>(), b.gen::<[u8; 20]>());
            assert_eq!(a.gen_range(7..99), b.gen_range(7..99));
            assert_eq!(a.gen_bool(0.3), b.gen_bool(0.3));
        }

        let (p1, p2, p3) = make_participants();
        let (rng1_l, rng1_r) = p1[SingleSpace].as_rngs();
        let (rng2_l, rng2_r) = p2[SingleSpace].as_rngs();
        let (rng3_l, rng3_r) = p3[SingleSpace].as_rngs();

        same_rng(rng1_l, rng3_r);
        same_rng(rng2_l, rng1_r);
        same_rng(rng3_l, rng2_r);
    }

    #[tokio::test]
    async fn different_prss() {
        // each time we create a step, it should generate a different prss
        let world: TestWorld<TestStep> = make_world(QueryId);
        let context = make_contexts(&world);

        let reshare0 = &context[0].participant[TestStep::Reshare(0)];
        let reshare1 = &context[0].participant[TestStep::Reshare(1)];
        let mul = &context[0].participant[TestStep::Mul2];

        assert_ne!(reshare0, reshare1);
        assert_ne!(reshare0, mul);
    }
}
