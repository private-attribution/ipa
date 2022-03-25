#[cfg(feature = "enable-serde")]
use crate::error::{Error, Res};
#[cfg(feature = "enable-serde")]
use crate::helpers::Helpers;
use crate::report::{DecryptedEventReport, DecryptedMatchkeys, EncryptedMatchkeys, EventReport};
use crate::threshold::DecryptionKey as ThresholdDecryptionKey;
use rand::thread_rng;
use rust_elgamal::EncryptionKey;
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

    #[must_use]
    pub fn threshold_decrypt_event(&self, r: &EventReport) -> EventReport {
        let partially_decrypted_matchkeys: EncryptedMatchkeys = r
            .encrypted_match_keys
            .threshold_decrypt(&self.matchkey_decrypt);
        EventReport {
            encrypted_match_keys: partially_decrypted_matchkeys,
        }
    }

    #[must_use]
    pub fn decrypt_event(&self, r: &EventReport) -> DecryptedEventReport {
        let decrypted_matchkeys: DecryptedMatchkeys =
            r.encrypted_match_keys.decrypt(&self.matchkey_decrypt);
        DecryptedEventReport {
            decrypted_match_keys: decrypted_matchkeys,
        }
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
    use crate::threshold::EncryptionKey as ThresholdEncryptionKey;
    use crate::user::User;

    #[test]
    fn test_the_basics() {
        const PROVIDER_1: &str = "social.example";
        const PROVIDER_2: &str = "news.example";
        const PROVIDER_3: &str = "email.example";
        const PROVIDER_4: &str = "game.example";
        const PROVIDER_5: &str = "404.example";

        const MATCHING_MATCHKEY: &str = "12345678";

        let h_source = Helper::new(Role::Source);
        let h_trigger = Helper::new(Role::Trigger);

        let tek = ThresholdEncryptionKey::new(&[
            h_source.public.matchkey_encrypt,
            h_trigger.public.matchkey_encrypt,
        ]);

        let mut u1 = User::new(1, tek);
        u1.set_matchkey(PROVIDER_1, MATCHING_MATCHKEY);
        u1.set_matchkey(PROVIDER_2, "23456789");
        u1.set_matchkey(PROVIDER_3, "34567890");
        u1.set_matchkey(PROVIDER_4, "45678901");

        let mut u2 = User::new(2, tek);
        u2.set_matchkey(PROVIDER_1, MATCHING_MATCHKEY);
        u2.set_matchkey(PROVIDER_2, "does_not_match");
        u2.set_matchkey(PROVIDER_3, "something_else");

        let r1 = u1.generate_event_report(&[PROVIDER_1, PROVIDER_2, PROVIDER_3, PROVIDER_4]);
        let r2 = u2.generate_event_report(&[PROVIDER_1, PROVIDER_2, PROVIDER_3, PROVIDER_5]);

        // Source Event Helper partially decrypts both events
        let partially_decrypted_1 = h_source.threshold_decrypt_event(&r1);
        let partially_decrypted_2 = h_source.threshold_decrypt_event(&r2);

        // At this point, none of the match keys should match
        assert_eq!(
            partially_decrypted_1
                .matchkeys()
                .count_matches(partially_decrypted_2.matchkeys()),
            0
        );

        // Trigger Event Helper partially decrypts both events
        let decrypted_1 = h_trigger.decrypt_event(&partially_decrypted_1);
        let decrypted_2 = h_trigger.decrypt_event(&partially_decrypted_2);

        // At this point, only the PROVIDER_1 match key should match
        assert_eq!(decrypted_1.matchkeys(), decrypted_2.matchkeys());
        assert_eq!(
            decrypted_1
                .matchkeys()
                .count_matches(decrypted_2.matchkeys()),
            1
        );
    }
}
