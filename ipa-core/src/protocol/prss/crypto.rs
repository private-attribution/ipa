use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes256,
};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{
    ff::{Field, GaloisField},
    secret_sharing::replicated::{
        semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing,
    },
};

pub trait SharedRandomness {
    /// Generate two random values, one that is known to the left helper
    /// and one that is known to the right helper.
    #[must_use]
    fn generate_values<I: Into<u128>>(&self, index: I) -> (u128, u128);

    /// Generate two random field values, one that is known to the left helper
    /// and one that is known to the right helper.
    #[must_use]
    fn generate_fields<F: Field, I: Into<u128>>(&self, index: I) -> (F, F) {
        let (l, r) = self.generate_values(index);
        (F::truncate_from(l), F::truncate_from(r))
    }

    /// Generate two sequences of random Fp2 bits.
    #[must_use]
    fn generate_bit_arrays<B: GaloisField, I: Into<u128>>(&self, index: I) -> (B, B) {
        let (l, r) = self.generate_values(index);
        (B::truncate_from(l), B::truncate_from(r))
    }

    ///
    /// Generate a replicated secret sharing of a random value, which none
    /// of the helpers knows. This is an implementation of the functionality 2.1 `F_rand`
    /// described on page 5 of the paper:
    /// "Efficient Bit-Decomposition and Modulus Conversion Protocols with an Honest Majority"
    /// by Ryo Kikuchi, Dai Ikarashi, Takahiro Matsuda, Koki Hamada, and Koji Chida
    /// <https://eprint.iacr.org/2018/387.pdf>
    ///
    #[must_use]
    fn generate_replicated<F: Field, I: Into<u128>>(&self, index: I) -> Replicated<F> {
        let (l, r) = self.generate_fields(index);
        Replicated::new(l, r)
    }

    /// Generate an additive share of zero.
    /// Each party generates two values, one that is shared with the party to their left,
    /// one with the party to their right.  If all entities add their left share
    /// and subtract their right value, each share will be added once (as a left share)
    /// and subtracted once (as a right share), resulting in values that sum to zero.
    #[must_use]
    fn zero_u128<I: Into<u128>>(&self, index: I) -> u128 {
        let (l, r) = self.generate_values(index);
        l.wrapping_sub(r)
    }

    /// Generate an XOR share of zero.
    #[must_use]
    fn zero_xor<I: Into<u128>>(&self, index: I) -> u128 {
        let (l, r) = self.generate_values(index);
        l ^ r
    }

    /// Generate an additive shares of a random value.
    /// This is like `zero_u128`, except that the values are added.
    /// The result is that each random value is added twice.  Note that thanks to
    /// using a wrapping add, the result won't be even because the high bit will
    /// wrap around and populate the low bit.
    #[must_use]
    fn random_u128<I: Into<u128>>(&self, index: I) -> u128 {
        let (l, r) = self.generate_values(index);
        l.wrapping_add(r)
    }

    /// Generate additive shares of zero in a field.
    #[must_use]
    fn zero<F: Field, I: Into<u128>>(&self, index: I) -> F {
        let (l, r): (F, F) = self.generate_fields(index);
        l - r
    }

    /// Generate additive shares of a random field value.
    #[must_use]
    fn random<F: Field, I: Into<u128>>(&self, index: I) -> F {
        let (l, r): (F, F) = self.generate_fields(index);
        l + r
    }
}

// The key exchange component of a participant.
pub struct KeyExchange {
    sk: EphemeralSecret,
}

impl KeyExchange {
    pub fn new<R: RngCore + CryptoRng>(r: &mut R) -> Self {
        Self {
            sk: EphemeralSecret::random_from_rng(r),
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
        let mut buf = index.to_le_bytes();
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut buf));

        u128::from_le_bytes(buf) ^ index
    }
}
