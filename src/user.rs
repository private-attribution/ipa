#[cfg(feature = "enable-serde")]
use crate::error::{Error, Result};
use crate::report::{EncryptedMatchkeys, EventReport};
use crate::threshold::{Ciphertext, EncryptionKey as ThresholdEncryptionKey, RistrettoPoint};
use hkdf::Hkdf;
use log::trace;
use rand::{thread_rng, RngCore};
#[cfg(feature = "enable-serde")]
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use std::collections::HashMap;
#[cfg(feature = "enable-serde")]
use std::fs;
#[cfg(feature = "enable-serde")]
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
    pub fn load(dir: &Path, uid: usize) -> Result<Self> {
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
    pub fn save(&self, dir: &Path) -> Result<()> {
        let f = self.filename(dir);
        fs::write(f, serde_json::to_string_pretty(self)?.as_bytes())?;
        Ok(())
    }

    /// This part ultimately needs to be standardized.
    /// This should do for now in terms of getting a good input.
    fn point_from_matchkey(provider: &str, mk: &[u8]) -> RistrettoPoint {
        let mut input = Vec::with_capacity(2 + provider.len() + mk.len());
        input.push(u8::try_from(provider.len()).unwrap());
        input.extend_from_slice(provider.as_bytes());
        input.push(u8::try_from(mk.len()).unwrap());
        input.extend_from_slice(mk);
        RistrettoPoint::hash_from_bytes::<Sha512>(&input)
    }

    pub fn set_matchkey(&mut self, provider: impl AsRef<str>, mk: impl AsRef<str>) {
        let m = Self::point_from_matchkey(provider.as_ref(), mk.as_ref().as_bytes());
        let emk = self.threshold_key.encrypt(m, &mut thread_rng());
        trace!(
            "User {}: set matchkey for '{}' to '{:?}'",
            self.id,
            provider.as_ref(),
            emk
        );
        if let Some(old) = self
            .encrypted_match_keys
            .insert(String::from(provider.as_ref()), emk)
        {
            trace!(
                "User {}: old matchkey for '{}' was '{:?}'",
                self.id,
                provider.as_ref(),
                old
            );
        }
    }

    /// Deterministically generate a fallback matchkey for a provider that
    /// hasn't set one.  This uses the fallback secret (`fallback_prk`) generated
    /// when the user was created.
    fn fallback_matchkey(&self, provider: &str) -> Ciphertext {
        let p = provider.as_bytes();
        // This method of generating `info` doesn't need to be standardized.
        // We're just treating HKDF as a PRG.
        let mut info = Vec::with_capacity(256);
        info.push(u8::try_from(p.len()).expect("provider names should be <256 bytes"));
        info.extend_from_slice(p);
        let mut mk = [0; 32];
        Hkdf::<Sha512>::from_prk(&self.fallback_prk)
            .unwrap() // prk came from Hkdf<Sha512>
            .expand(&info, &mut mk)
            .unwrap(); // length is valid
        let m = Self::point_from_matchkey(provider, &mk);
        self.threshold_key.encrypt(m, &mut thread_rng())
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
            .unwrap_or_else(|| self.fallback_matchkey(provider));
        self.threshold_key.rerandomise(emk, &mut rng)
    }

    #[must_use]
    pub fn generate_event_report(&self, providers: &[&str]) -> EventReport {
        let m: HashMap<_, _> = providers
            .iter()
            .map(|p| ((*p).to_string(), self.encrypt_matchkey(p)))
            .collect();
        EventReport {
            encrypted_match_keys: EncryptedMatchkeys::from_matchkeys(m),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::User;
    use crate::threshold::{
        DecryptionKey as ThresholdDecryptionKey, EncryptionKey as ThresholdEncryptionKey,
        RistrettoPoint,
    };
    use rand::thread_rng;

    const MATCHKEY: &str = "matchkey";
    const PROVIDER: &str = "example.com";

    fn default_matchkey() -> RistrettoPoint {
        User::point_from_matchkey(PROVIDER, MATCHKEY.as_bytes())
    }

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
        assert_eq!(complete1, default_matchkey());

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
        assert_eq!(complete1, default_matchkey());

        let partial2 = d1.threshold_decrypt(c2);
        let complete2 = d2.decrypt(partial2);
        assert_eq!(complete1, complete2);
        assert_eq!(complete2, default_matchkey());
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
        assert_ne!(complete1, default_matchkey());

        let partial2 = d1.threshold_decrypt(c2);
        let complete2 = d2.decrypt(partial2);
        assert_eq!(complete1, complete2);
        assert_ne!(complete2, default_matchkey());
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
        assert_ne!(complete1, default_matchkey());

        let partial2 = d1.threshold_decrypt(c2);
        let complete2 = d2.decrypt(partial2);
        assert_ne!(complete1, complete2);
        assert_ne!(
            complete2,
            User::point_from_matchkey(OTHER_PROVIDER, MATCHKEY.as_bytes())
        );
    }

    #[test]
    fn generate_event_report() {
        const PROVIDER_1: &str = "social.example";
        const PROVIDER_2: &str = "email.example";
        const PROVIDER_3: &str = "news.example";
        const MATCHING_MATCHKEY: &str = "this_one_matches";

        let mut rng = thread_rng();
        let d1 = ThresholdDecryptionKey::new(&mut rng);
        let d2 = ThresholdDecryptionKey::new(&mut rng);
        let tek = ThresholdEncryptionKey::new(&[d1.encryption_key(), d2.encryption_key()]);

        let providers = [PROVIDER_1, PROVIDER_2, PROVIDER_3];

        let mut u1 = User::new(0, tek);
        u1.set_matchkey(PROVIDER_1, MATCHING_MATCHKEY);
        u1.set_matchkey(PROVIDER_2, "something_random");
        u1.set_matchkey(PROVIDER_3, "also_very_random");

        let mut u2 = User::new(1, tek);
        u2.set_matchkey(PROVIDER_1, MATCHING_MATCHKEY);
        u2.set_matchkey(PROVIDER_2, "does_not_match");
        u2.set_matchkey(PROVIDER_3, "also_does_not_match");

        let r1 = u1.generate_event_report(&providers);
        let r2 = u2.generate_event_report(&providers);

        // No combination of encrypted match keys should match
        assert_eq!(r1.matchkeys().count_matches(r2.matchkeys()), 0,);

        let fully_decrypted_r1 = r1.matchkeys().threshold_decrypt(&d1).decrypt(&d2);
        let fully_decrypted_r2 = r2.matchkeys().threshold_decrypt(&d1).decrypt(&d2);

        // Once fully decrypted, only one combination should match
        assert_eq!(fully_decrypted_r1, fully_decrypted_r2,);
        assert_eq!(fully_decrypted_r1.count_matches(&fully_decrypted_r2), 1,);
    }
}
