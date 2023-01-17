use crate::ff::Field;
use crate::rand::{CryptoRng, RngCore};
use crate::secret_sharing::Replicated;

use std::fmt::Debug;

use x25519_dalek::{EphemeralSecret, PublicKey};

pub trait SharedRandomness {
    /// Generate two random values, one that is known to the left helper
    /// and one that is known to the right helper.
    #[must_use]
    fn generate_values<I: Into<u128>>(&self, index: I) -> (u128, u128);

    #[must_use]
    fn generate_fields<F: Field, I: Into<u128>>(&self, _index: I) -> (F, F) {
        (F::ZERO, F::ZERO)
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

    #[must_use]
    fn zero_u128<I: Into<u128>>(&self, _index: I) -> u128 {
        0
    }

    #[must_use]
    fn zero_xor<I: Into<u128>>(&self, _index: I) -> u128 {
        0
    }

    #[must_use]
    fn random_u128<I: Into<u128>>(&self, _index: I) -> u128 {
        0
    }

    #[must_use]
    fn zero<F: Field, I: Into<u128>>(&self, _index: I) -> F {
        F::ZERO
    }

    #[must_use]
    fn random<F: Field, I: Into<u128>>(&self, _index: I) -> F {
        F::ZERO
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
    pub fn key_exchange(self, _pk: &PublicKey) -> GeneratorFactory {
        GeneratorFactory {}
    }
}

pub struct GeneratorFactory {}

impl GeneratorFactory {
    #[must_use]
    pub fn generator(&self, _context: &[u8]) -> Generator {
        Generator {}
    }
}

#[derive(Debug, Clone)]
pub struct Generator {}
/// The basic generator.  This generates values based on an arbitrary index.
impl Generator {
    /// Generate the value at the given index.
    /// This uses the MMO^{\pi} function described in <https://eprint.iacr.org/2019/074>.
    #[must_use]
    pub fn generate(&self, _index: u128) -> u128 {
        0
    }
}
