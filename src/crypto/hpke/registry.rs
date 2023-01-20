use super::{IpaKem, IpaPrivateKey, IpaPublicKey, KeyIdentifier};
use crate::crypto::hpke::Epoch;
use hpke::Kem;
use rand::{CryptoRng, RngCore};
use std::collections::HashMap;

/// A pair of secret key and public key. Public keys used by UA to encrypt the data towards helpers
/// secret keys used by helpers to open the ciphertexts. Each helper needs access to both
/// TODO: we may decide to use different HPKE settings for each key identifier.
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
    pub(super) fn public_key(&self) -> &IpaPublicKey {
        &self.pk
    }

    pub(super) fn private_key(&self) -> &IpaPrivateKey {
        &self.sk
    }
}

/// A registry that holds all the keys available for helper/UA to use.
/// Keys are partitioned per epoch.
pub struct KeyRegistry {
    keys: HashMap<Epoch, Box<[KeyPair]>>,
}

impl KeyRegistry {
    #[cfg(any(test, feature = "test-fixture"))]
    pub fn random<R: RngCore + CryptoRng>(
        epochs: Epoch,
        keys_per_epoch: usize,
        mut r: &mut R,
    ) -> Self {
        let mut generate_keys = || -> Vec<KeyPair> {
            (0..keys_per_epoch)
                .map(|_| <IpaKem as Kem>::gen_keypair(&mut r).into())
                .collect::<Vec<_>>()
        };

        let keys = (0..epochs)
            .map(|epoch| (epoch, generate_keys().into_boxed_slice()))
            .collect::<HashMap<_, _>>();

        Self { keys }
    }

    #[must_use]
    pub(super) fn private_key(&self, epoch: Epoch, key_id: KeyIdentifier) -> &IpaPrivateKey {
        self.key_pair(epoch, key_id).private_key()
    }

    #[must_use]
    pub fn public_key(&self, epoch: Epoch, key_id: KeyIdentifier) -> &IpaPublicKey {
        self.key_pair(epoch, key_id).public_key()
    }

    fn key_pair(&self, epoch: Epoch, key_id: KeyIdentifier) -> &KeyPair {
        self.keys
            .get(&epoch)
            .and_then(|keys| keys.get(key_id as usize))
            .unwrap_or_else(|| {
                panic!("no key registered for epoch '{epoch}' and key id '{key_id}'")
            })
    }
}
