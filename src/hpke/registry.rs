use super::{IpaPrivateKey, IpaPublicKey, KeyIdentifier};
use hpke::Serializable;

/// A pair of secret key and public key. Public keys used by UA to encrypt the data towards helpers
/// secret keys used by helpers to open the ciphertexts. Each helper needs access to both
pub struct KeyPair {
    pk: IpaPublicKey,
    sk: IpaPrivateKey,
}

impl From<(IpaPrivateKey, IpaPublicKey)> for KeyPair {
    fn from(value: (IpaPrivateKey, IpaPublicKey)) -> Self {
        Self {
            pk: value.1,
            sk: value.0,
        }
    }
}

impl KeyPair {
    pub fn gen<R: rand::RngCore + rand::CryptoRng>(mut r: &mut R) -> Self {
        <super::IpaKem as hpke::Kem>::gen_keypair(&mut r).into()
    }

    /// Returns the public key bytes. With X25519 crate it is possible to borrow those bytes, but
    /// hpke crate wraps those types and does not offer `as_bytes`.
    #[must_use]
    pub fn pk_bytes(&self) -> Box<[u8]> {
        let pk_bytes: [u8; 32] = self.pk.to_bytes().into();
        Box::new(pk_bytes)
    }

    /// Returns the secret key bytes, for the same reason as [`pk_bytes`] it returns an owned slice,
    /// instead of borrow.
    ///
    /// [`pk_bytes`]: Self::pk_bytes
    #[must_use]
    pub fn sk_bytes(&self) -> Box<[u8]> {
        let sk_bytes: [u8; 32] = self.sk.to_bytes().into();
        Box::new(sk_bytes)
    }
}

/// A registry that holds all the keys available for helper/UA to use.
pub struct KeyRegistry {
    keys: Box<[KeyPair]>,
}

impl KeyRegistry {
    #[cfg(any(test, feature = "test-fixture"))]
    pub fn random<R: rand::RngCore + rand::CryptoRng>(keys_count: usize, r: &mut R) -> Self {
        let keys = (0..keys_count).map(|_| KeyPair::gen(r)).collect::<Vec<_>>();

        Self {
            keys: keys.into_boxed_slice(),
        }
    }

    #[must_use]
    pub(super) fn private_key(&self, key_id: KeyIdentifier) -> Option<&IpaPrivateKey> {
        self.key_pair(key_id).map(|v| &v.sk)
    }

    #[must_use]
    pub fn public_key(&self, key_id: KeyIdentifier) -> Option<&IpaPublicKey> {
        self.key_pair(key_id).map(|v| &v.pk)
    }

    fn key_pair(&self, key_id: KeyIdentifier) -> Option<&KeyPair> {
        match key_id as usize {
            key_id if key_id < self.keys.len() => Some(&self.keys[key_id]),
            _ => None,
        }
    }
}
