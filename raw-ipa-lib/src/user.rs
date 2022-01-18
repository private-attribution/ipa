use crate::error::{Error, Res};
use crate::threshold::{Ciphertext, RistrettoPoint, ThresholdEncryptionKey};
use rand::thread_rng;
#[cfg(feature = "enable-serde")]
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use std::collections::HashMap;
#[cfg(feature = "enable-serde")]
use std::fs;
use std::path::{Path, PathBuf};

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct User {
    id: usize,
    threshold_key: ThresholdEncryptionKey,
    encrypted_match_keys: HashMap<String, Ciphertext>,
}

impl User {
    fn filename_for(dir: &Path, uid: usize) -> PathBuf {
        let mut f = PathBuf::from(dir);
        f.push(format!("{}.json", uid));
        f
    }

    #[cfg(feature = "enable-serde")]
    #[must_use]
    pub fn filename(&self, dir: &Path) -> PathBuf {
        Self::filename_for(dir, self.id)
    }

    /// # Errors
    /// When a file for the given ID already exists.
    #[must_use]
    pub fn new(id: usize, threshold_key: ThresholdEncryptionKey) -> Self {
        Self {
            id,
            threshold_key,
            encrypted_match_keys: HashMap::default(),
        }
    }

    /// # Errors
    /// When the file is invalid JSON, or when it contains a bad ID.
    #[cfg(feature = "enable-serde")]
    pub fn load(dir: &Path, uid: usize) -> Res<Self> {
        let f = Self::filename_for(dir, uid);
        let s = fs::read_to_string(f)?;
        let v: Self = serde_json::from_str(&s)?;
        if v.id != uid {
            return Err(Error::InvalidId);
        }
        Ok(v)
    }

    /// # Errors
    /// When the file cannot be written.
    #[cfg(feature = "enable-serde")]
    pub fn save(&self, dir: &Path) -> Res<()> {
        let f = self.filename(dir);
        fs::write(f, serde_json::to_string(self)?.as_bytes())?;
        Ok(())
    }

    pub fn set_matchkey(&mut self, origin: &str, match_key: &[u8; 32]) {
        // Note that ristretto wants 64 bytes of input; also we don't know if the input is uniform.
        // TODO: Consider salting this input somehow (with the origin, perhaps).
        //       The caveat being that anything we do needs to be standardized.
        let m = RistrettoPoint::hash_from_bytes::<Sha512>(&match_key[..]);
        let emk = self.threshold_key.encrypt(m, &mut thread_rng());
        self.encrypted_match_keys.insert(String::from(origin), emk);
    }

    /// Create an encrypted matchkey for the identified origin.
    #[must_use]
    pub fn encrypt_matchkey(&self, origin: &str) -> Ciphertext {
        let mut rng = thread_rng();
        // TODO: determine if we need to hide the timing sidechannel here.
        if let Some(emk) = self.encrypted_match_keys.get(origin) {
            self.threshold_key.rerandomise(*emk, &mut rng)
        } else {
            Ciphertext::from((
                RistrettoPoint::random(&mut rng),
                RistrettoPoint::random(&mut rng),
            ))
        }
    }
}
