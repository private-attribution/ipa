use std::collections::HashMap;
use crate::error::{Error, Res};
#[cfg(feature = "enable-serde")]
use crate::helpers::Helpers;
use crate::threshold::DecryptionKey as ThresholdDecryptionKey;
use crate::user::DecryptedEventReport;
use crate::user::EventReport;
use rand::thread_rng;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rust_elgamal::{Ciphertext, EncryptionKey, RistrettoPoint, Scalar, GENERATOR_POINT};
#[cfg(feature = "enable-serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "enable-serde")]
use std::fs;
use std::ops::{Deref, DerefMut};
#[cfg(feature = "enable-serde")]
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub enum Role {
    Source,
    Trigger,
}

/// All of the public information about an event helper.
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct PublicHelper {
    role: Role,
    matchkey_encrypt: EncryptionKey,
}

impl PublicHelper {
    #[must_use]
    pub fn matchkey_encryption_key(&self) -> EncryptionKey {
        self.matchkey_encrypt
    }
}

/// A source or trigger event helper.
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct Helper {
    #[cfg_attr(feature = "enable-serde", serde(flatten))]
    public: PublicHelper,

    matchkey_decrypt: ThresholdDecryptionKey,
}

impl Helper {
    #[must_use]
    pub fn new(role: Role) -> Self {
        let matchkey_decrypt = ThresholdDecryptionKey::new(&mut thread_rng());
        Self {
            public: PublicHelper {
                role,
                matchkey_encrypt: matchkey_decrypt.encryption_key(),
            },
            matchkey_decrypt,
        }
    }

    /// # Errors
    /// Missing or badly formatted files.
    #[cfg(feature = "enable-serde")]
    pub fn load(dir: &Path, role: Role) -> Res<Self> {
        let s = fs::read_to_string(&Helpers::filename(dir, false))?;
        let v: Self = serde_json::from_str(&s)?;
        if role != v.public.role {
            return Err(Error::InvalidRole);
        }
        Ok(v)
    }

    /// # Errors
    /// Unable to write files.
    #[cfg(feature = "enable-serde")]
    pub fn save(&self, dir: &Path) -> Res<()> {
        let f = Helpers::filename(dir, true);
        fs::write(f, serde_json::to_string_pretty(&self.public)?.as_bytes())?;
        let f = Helpers::filename(dir, false);
        fs::write(f, serde_json::to_string_pretty(&self)?.as_bytes())?;
        Ok(())
    }

    pub fn threshold_decrypt_event(&self, r: EventReport) -> EventReport {
        let partially_decrypted_matchkeys: HashMap<_, _> = r.encrypted_match_keys.iter().map(
            |(p, emk)| (p.to_string(), self.matchkey_decrypt.threshold_decrypt(*emk))
        ).collect();
        EventReport{encrypted_match_keys: partially_decrypted_matchkeys}
    }

    pub fn decrypt_event(&self, r: EventReport) -> DecryptedEventReport {
        let partially_decrypted_matchkeys: HashMap<_, _> = r.encrypted_match_keys.iter().map(
            |(p, emk)| (p.to_string(), self.matchkey_decrypt.decrypt(*emk))
        ).collect();
        DecryptedEventReport{decrypted_match_keys: partially_decrypted_matchkeys}
    }
}

impl Deref for Helper {
    type Target = PublicHelper;
    fn deref(&self) -> &Self::Target {
        &self.public
    }
}

impl DerefMut for Helper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.public
    }
}

#[cfg(test)]
mod tests {
    use super::{Helper, Role};
    use crate::user::User;
    use crate::user::EventReport;
        use crate::threshold::{
        DecryptionKey as ThresholdDecryptionKey, EncryptionKey as ThresholdEncryptionKey,
    };
    pub use rust_elgamal::{Ciphertext, EncryptionKey, RistrettoPoint, Scalar, GENERATOR_POINT};
    use rand::thread_rng;

    #[test]
    fn test_the_basics() {
        let h_se = Helper::new(Role::Source);
        let h_te = Helper::new(Role::Trigger);

        let tek = ThresholdEncryptionKey::new(&[h_se.public.matchkey_encrypt, h_te.public.matchkey_encrypt]);

        const PROVIDER_1: &str = "social.example";
        const PROVIDER_2: &str = "news.example";
        const PROVIDER_3: &str = "email.example";
        const PROVIDER_4: &str = "game.example";

        const MATCHING_MATCHKEY: &str = "12345678";

        let mut u123 = User::new(123, tek);
        u123.set_matchkey(PROVIDER_1, MATCHING_MATCHKEY);
        u123.set_matchkey(PROVIDER_2, "23456789");
        u123.set_matchkey(PROVIDER_3, "34567890");
        u123.set_matchkey(PROVIDER_4, "45678901");

        let mut u234 = User::new(234, tek);
        u234.set_matchkey(PROVIDER_1, MATCHING_MATCHKEY);
        u234.set_matchkey(PROVIDER_2, "does_not_match");
        u234.set_matchkey(PROVIDER_3, "something_else");

        let r123 = u123.generate_event_report(&[PROVIDER_1, PROVIDER_2, PROVIDER_3, PROVIDER_4]);
        let r234 = u234.generate_event_report(&[PROVIDER_1, PROVIDER_2, PROVIDER_3]);

        // Source Event Helper partially decrypts both events
        let partially_decrypted_123 = h_se.threshold_decrypt_event(r123);
        let partially_decrypted_234 = h_se.threshold_decrypt_event(r234);

        // At this point, none of the match keys should match
        assert_ne!(
            partially_decrypted_123.encrypted_match_keys.get(PROVIDER_1),
            partially_decrypted_234.encrypted_match_keys.get(PROVIDER_1),
        );
        assert_ne!(
            partially_decrypted_123.encrypted_match_keys.get(PROVIDER_2),
            partially_decrypted_234.encrypted_match_keys.get(PROVIDER_2),
        );
        assert_ne!(
            partially_decrypted_123.encrypted_match_keys.get(PROVIDER_3),
            partially_decrypted_234.encrypted_match_keys.get(PROVIDER_3),
        );
        assert_ne!(
            partially_decrypted_123.encrypted_match_keys.get(PROVIDER_4),
            partially_decrypted_234.encrypted_match_keys.get(PROVIDER_4),
        );

        // Trigger Event Helper partially decrypts both events
        let decrypted_123 = h_te.decrypt_event(partially_decrypted_123);
        let decrypted_234 = h_te.decrypt_event(partially_decrypted_234);

        // At this point, only the PROVIDER_1 match key should match
        assert_eq!(
            decrypted_123.decrypted_match_keys.get(PROVIDER_1),
            decrypted_234.decrypted_match_keys.get(PROVIDER_1),
        );
        assert_ne!(
            decrypted_123.decrypted_match_keys.get(PROVIDER_2),
            decrypted_234.decrypted_match_keys.get(PROVIDER_2),
        );
        assert_ne!(
            decrypted_123.decrypted_match_keys.get(PROVIDER_3),
            decrypted_234.decrypted_match_keys.get(PROVIDER_3),
        );
        assert_ne!(
            decrypted_123.decrypted_match_keys.get(PROVIDER_4),
            decrypted_234.decrypted_match_keys.get(PROVIDER_4),
        );
    }
}
