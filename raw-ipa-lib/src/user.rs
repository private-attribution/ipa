#[cfg(feature = "enable-serde")]
use crate::error::{Error, Res};
use crate::threshold::{Ciphertext, EncryptionKey as ThresholdEncryptionKey, RistrettoPoint};
use hkdf::Hkdf;
use rand::{thread_rng, RngCore};
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
    fallback_prk: Vec<u8>,
}

impl User {
    #[cfg(feature = "enable-serde")]
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
        let mut ikm = [0; 64];
        thread_rng().fill_bytes(&mut ikm);
        let (prk, _) = Hkdf::<Sha512>::extract(None, &ikm);
        Self {
            id,
            threshold_key,
            encrypted_match_keys: HashMap::default(),
            fallback_prk: prk.to_vec(),
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
        fs::write(f, serde_json::to_string_pretty(self)?.as_bytes())?;
        Ok(())
    }

    fn point_from_matchkey(mk: &[u8; 32]) -> RistrettoPoint {
        // Note that ristretto wants 64 bytes of input; also we don't know if the input is uniform.
        // TODO: Consider salting this input somehow (with the provider, perhaps).
        //       The caveat being that anything we do needs to be standardized.
        RistrettoPoint::hash_from_bytes::<Sha512>(&mk[..])
    }

    pub fn set_matchkey(&mut self, provider: &str, mk: &[u8; 32]) {
        let m = Self::point_from_matchkey(mk);
        let emk = self.threshold_key.encrypt(m, &mut thread_rng());
        self.encrypted_match_keys
            .insert(String::from(provider), emk);
    }

    /// Create an encrypted matchkey for the identified provider.
    /// # Panics
    /// If the provider name is >= 256 bytes.
    #[must_use]
    pub fn encrypt_matchkey(&self, provider: &str) -> Ciphertext {
        let mut rng = thread_rng();
        // TODO: determine if we need to hide the timing sidechannel here.
        let emk = self
            .encrypted_match_keys
            .get(provider)
            .copied()
            .unwrap_or_else(|| {
                let p_bytes = provider.as_bytes();
                // This method of generating `info` doesn't need to be standardized.
                // We're just treating HKDF as a PRG.
                let mut info = Vec::with_capacity(256);
                info.push(
                    u8::try_from(p_bytes.len()).expect("provider names should be <256 bytes"),
                );
                info.extend_from_slice(p_bytes);
                let mut mk = [0; 32];
                Hkdf::<Sha512>::from_prk(&self.fallback_prk)
                    .unwrap() // prk came from Hkdf<Sha512>
                    .expand(&info, &mut mk)
                    .unwrap(); // length is valid
                let m = Self::point_from_matchkey(&mk);
                self.threshold_key.encrypt(m, &mut thread_rng())
            });
        self.threshold_key.rerandomise(emk, &mut rng)
    }
}

#[cfg(test)]
mod tests {
    use super::User;
    use crate::threshold::{
        DecryptionKey as ThresholdDecryptionKey, EncryptionKey as ThresholdEncryptionKey,
    };
    use rand::thread_rng;

    const MATCHKEY: &[u8; 32] = &[0; 32];
    const PROVIDER: &str = "example.com";

    /// Match keys can be decrypted in any order.
    #[test]
    fn matchkey_two_keys() {
        let mut rng = thread_rng();
        let d1 = ThresholdDecryptionKey::new(&mut rng);
        let d2 = ThresholdDecryptionKey::new(&mut rng);
        let tek = ThresholdEncryptionKey::new(&[d1.encryption_key(), d2.encryption_key()]);
        let mut u = User::new(0, tek);
        u.set_matchkey(PROVIDER, MATCHKEY);

        let c = u.encrypt_matchkey(PROVIDER);
        let partial1 = d1.threshold_decrypt(c);
        let complete1 = d2.decrypt(partial1);
        assert_eq!(complete1, User::point_from_matchkey(MATCHKEY));

        // A redundant check that ordering doesn't matter.
        let partial2 = d2.threshold_decrypt(c);
        let complete2 = d1.decrypt(partial2);
        assert_eq!(complete1, complete2);
    }

    /// Two encrypted match keys appear to be random.
    #[test]
    fn matchkey_two_encryptions() {
        let mut rng = thread_rng();
        let d1 = ThresholdDecryptionKey::new(&mut rng);
        let d2 = ThresholdDecryptionKey::new(&mut rng);
        let tek = ThresholdEncryptionKey::new(&[d1.encryption_key(), d2.encryption_key()]);
        let mut u = User::new(0, tek);
        u.set_matchkey(PROVIDER, MATCHKEY);

        let c1 = u.encrypt_matchkey(PROVIDER);
        let c2 = u.encrypt_matchkey(PROVIDER);
        assert_ne!(c1, c2, "ciphertext should be different");

        let partial1 = d1.threshold_decrypt(c1);
        let complete1 = d2.decrypt(partial1);
        assert_eq!(complete1, User::point_from_matchkey(MATCHKEY));

        let partial2 = d1.threshold_decrypt(c2);
        let complete2 = d2.decrypt(partial2);
        assert_eq!(complete1, complete2);
        assert_eq!(complete2, User::point_from_matchkey(MATCHKEY));
    }

    /// When no matchkey is set the encrypted matchkey appears different,
    /// but decrypts to the same value, which is generated deterministically.
    #[test]
    fn matchkey_fallback() {
        let mut rng = thread_rng();
        let d1 = ThresholdDecryptionKey::new(&mut rng);
        let d2 = ThresholdDecryptionKey::new(&mut rng);
        let tek = ThresholdEncryptionKey::new(&[d1.encryption_key(), d2.encryption_key()]);
        let u = User::new(0, tek);
        // no matchkeys set here

        let c1 = u.encrypt_matchkey(PROVIDER);
        let c2 = u.encrypt_matchkey(PROVIDER);
        assert_ne!(c1, c2, "ciphertext should be different");

        let partial1 = d1.threshold_decrypt(c1);
        let complete1 = d2.decrypt(partial1);
        assert_ne!(complete1, User::point_from_matchkey(MATCHKEY));

        let partial2 = d1.threshold_decrypt(c2);
        let complete2 = d2.decrypt(partial2);
        assert_eq!(complete1, complete2);
        assert_ne!(complete2, User::point_from_matchkey(MATCHKEY));
    }

    #[test]
    fn different_provider_fallback() {
        const OTHER_PROVIDER: &str = "other.example";

        let mut rng = thread_rng();
        let d1 = ThresholdDecryptionKey::new(&mut rng);
        let d2 = ThresholdDecryptionKey::new(&mut rng);
        let tek = ThresholdEncryptionKey::new(&[d1.encryption_key(), d2.encryption_key()]);
        let u = User::new(0, tek);
        // no matchkeys set here

        assert_ne!(PROVIDER, OTHER_PROVIDER);
        let c1 = u.encrypt_matchkey(PROVIDER);
        let c2 = u.encrypt_matchkey(OTHER_PROVIDER);
        assert_ne!(c1, c2, "ciphertext should be different");

        let partial1 = d1.threshold_decrypt(c1);
        let complete1 = d2.decrypt(partial1);
        assert_ne!(complete1, User::point_from_matchkey(MATCHKEY));

        let partial2 = d1.threshold_decrypt(c2);
        let complete2 = d2.decrypt(partial2);
        assert_ne!(complete1, complete2);
        assert_ne!(complete2, User::point_from_matchkey(MATCHKEY));
    }
}
