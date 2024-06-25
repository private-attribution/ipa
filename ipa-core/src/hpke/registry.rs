use std::ops::Deref;

use hpke::Serializable;

use super::{IpaPrivateKey, IpaPublicKey, KeyIdentifier};

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

// This newtype is necessary because IpaPublicKey is an associated type from another crate (hpke).
// The coherence rules prohibit us from implementing `PublicKeyRegistry` both for our concrete type
// `KeyPair` and for `IpaPublicKey`, because the impls would overlap if hpke chose to define
// `IpaPublicKey` to be the same as `KeyPair`.
pub struct PublicKeyOnly(pub IpaPublicKey);

impl Deref for PublicKeyOnly {
    type Target = IpaPublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// This newtype is necessary because IpaPrivateKey is an associated type from another crate (hpke).
// The coherence rules prohibit us from implementing `PrivateKeyRegistry` both for our concrete type
// `KeyPair` and for `IpaPrivateKey`, because the impls would overlap if hpke chose to define
// `IpaPrivateKey` to be the same as `KeyPair`.
pub struct PrivateKeyOnly(pub IpaPrivateKey);

impl Deref for PrivateKeyOnly {
    type Target = IpaPrivateKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&KeyRegistry<KeyPair>> for KeyRegistry<PrivateKeyOnly> {
    fn from(key_registry: &KeyRegistry<KeyPair>) -> Self {
        let keys = key_registry
            .keys
            .iter()
            .map(|k| PrivateKeyOnly(k.sk.clone()))
            .collect::<Vec<_>>();
        Self {
            keys: keys.into_boxed_slice(),
        }
    }
}

pub trait PublicKeyRegistry {
    fn public_key(&self, key_id: KeyIdentifier) -> Option<&IpaPublicKey>;
}

pub trait PrivateKeyRegistry: Send + Sync + 'static {
    fn private_key(&self, key_id: KeyIdentifier) -> Option<&IpaPrivateKey>;
}

/// A registry that holds all the keys available for helper/UA to use.
pub struct KeyRegistry<K> {
    keys: Box<[K]>,
}

impl<K> KeyRegistry<K> {
    /// Create a key registry with no keys. Since the registry is immutable, it is useless,
    /// but this avoids `Option<KeyRegistry>` when the registry is ultimately not optional.
    #[must_use]
    pub fn empty() -> Self {
        Self { keys: Box::new([]) }
    }

    pub fn from_keys<const N: usize, I: Into<K>>(pairs: [I; N]) -> Self {
        Self {
            keys: pairs
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }

    fn key(&self, key_id: KeyIdentifier) -> Option<&K> {
        match key_id as usize {
            key_id if key_id < self.keys.len() => Some(&self.keys[key_id]),
            _ => None,
        }
    }
}

impl KeyRegistry<KeyPair> {
    #[cfg(any(test, feature = "test-fixture"))]
    pub fn random<R: rand::RngCore + rand::CryptoRng>(keys_count: usize, r: &mut R) -> Self {
        let keys = (0..keys_count).map(|_| KeyPair::gen(r)).collect::<Vec<_>>();

        Self {
            keys: keys.into_boxed_slice(),
        }
    }
}

impl PrivateKeyRegistry for KeyRegistry<KeyPair> {
    #[must_use]
    fn private_key(&self, key_id: KeyIdentifier) -> Option<&IpaPrivateKey> {
        self.key(key_id).map(|v| &v.sk)
    }
}

impl PrivateKeyRegistry for KeyRegistry<PrivateKeyOnly> {
    #[must_use]
    fn private_key(&self, key_id: KeyIdentifier) -> Option<&IpaPrivateKey> {
        self.key(key_id).map(|sk| &**sk)
    }
}

impl PublicKeyRegistry for KeyRegistry<KeyPair> {
    fn public_key(&self, key_id: KeyIdentifier) -> Option<&IpaPublicKey> {
        self.key(key_id).map(|v| &v.pk)
    }
}

impl PublicKeyRegistry for KeyRegistry<PublicKeyOnly> {
    fn public_key(&self, key_id: KeyIdentifier) -> Option<&IpaPublicKey> {
        self.key(key_id).map(|pk| &**pk)
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use hpke::{HpkeError, OpModeR, OpModeS};
    use rand::rngs::StdRng;
    use rand_core::{CryptoRng, RngCore, SeedableRng};

    use super::*;
    use crate::hpke::{IpaAead, IpaEncapsulatedKey, IpaKdf, IpaKem};

    const INFO_STR: &[u8] = b"This is an INFO string.";
    const AAD: &[u8] = b"This is AAD.";

    fn encrypt<R: RngCore + CryptoRng>(
        pk: &IpaPublicKey,
        pt: &[u8],
        r: &mut R,
    ) -> (IpaEncapsulatedKey, Vec<u8>) {
        let (encapsulated_key, mut encryption_context) =
            hpke::setup_sender::<IpaAead, IpaKdf, IpaKem, _>(&OpModeS::Base, pk, INFO_STR, r)
                .expect("Can setup the sender.");

        (
            encapsulated_key,
            encryption_context
                .seal(pt, AAD)
                .expect("Encryption failed."),
        )
    }

    fn decrypt<I: AsRef<[u8]>>(
        sk: &IpaPrivateKey,
        payload: &(IpaEncapsulatedKey, I),
    ) -> Result<Vec<u8>, HpkeError> {
        let (encap_key, ct) = payload;
        let mut decryption_context = hpke::setup_receiver::<IpaAead, IpaKdf, IpaKem>(
            &OpModeR::Base,
            sk,
            encap_key,
            INFO_STR,
        )
        .expect("Can setup the receiver.");

        decryption_context.open(ct.as_ref(), AAD)
    }

    #[test]
    fn encrypt_decrypt() {
        let mut rng = StdRng::seed_from_u64(42);
        let keypair1 = KeyPair::gen(&mut rng);
        let keypair2 = KeyPair::gen(&mut rng);

        let registry = KeyRegistry::<KeyPair>::from_keys([keypair1, keypair2]);
        let pt = b"This is a plaintext.";
        let ct_payload = encrypt(registry.public_key(0).unwrap(), pt, &mut rng);
        assert_eq!(
            Ok(pt.to_vec()),
            decrypt(registry.private_key(0).unwrap(), &ct_payload)
        );

        assert_eq!(
            HpkeError::OpenError,
            decrypt(registry.private_key(1).unwrap(), &ct_payload).unwrap_err()
        );
    }
}
