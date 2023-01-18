use crate::ff::Field;
use crate::rand::{CryptoRng, RngCore};
use crate::secret_sharing::replicated::semi_honest::AdditiveShare as Replicated;

use std::fmt::Debug;

use x25519_dalek::PublicKey;

/// This is a no-op prss implementation which has been introduced for performance testing of protocols to isolate any PRSS related bottlenecks.
pub trait SharedRandomness {
    #[must_use]
    fn generate_values<I: Into<u128>>(&self, index: I) -> (u128, u128);

    #[must_use]
    fn generate_fields<F: Field, I: Into<u128>>(&self, _index: I) -> (F, F) {
        (F::ZERO, F::ZERO)
    }

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
pub struct KeyExchange {}

impl KeyExchange {
    pub fn new<R: RngCore + CryptoRng>(_r: &mut R) -> Self {
        Self {}
    }

    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from([0_u8; 32])
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
impl Generator {
    #[must_use]
    pub fn generate(&self, _index: u128) -> u128 {
        0
    }
}
