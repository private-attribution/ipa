use crate::threshold::DecryptionKey as ThresholdDecryptionKey;
use crate::threshold::{Ciphertext, RistrettoPoint};

use std::collections::HashMap;
use std::fmt;

pub struct EncryptedMatchkeys {
    match_keys: HashMap<String, Ciphertext>,
}

impl PartialEq for EncryptedMatchkeys {
    fn eq(&self, other: &Self) -> bool {
        any_matches(self.match_keys.values(), &other.match_keys.values())
    }
}

impl EncryptedMatchkeys {
    pub fn count_matches(&self, other: &Self) -> usize {
        n_matches(self.match_keys.values(), &other.match_keys.values())
    }

    pub fn from_matchkeys(match_keys: HashMap<String, Ciphertext>) -> EncryptedMatchkeys {
        EncryptedMatchkeys { match_keys }
    }

    pub fn threshold_decrypt(
        &self,
        matchkey_decrypt: &ThresholdDecryptionKey,
    ) -> EncryptedMatchkeys {
        let partially_decrypted_matchkeys = self
            .match_keys
            .iter()
            .map(|(p, emk)| (p.to_string(), matchkey_decrypt.threshold_decrypt(*emk)))
            .collect();
        EncryptedMatchkeys::from_matchkeys(partially_decrypted_matchkeys)
    }

    pub fn decrypt(&self, matchkey_decrypt: &ThresholdDecryptionKey) -> DecryptedMatchkeys {
        let decrypted_matchkeys = self
            .match_keys
            .iter()
            .map(|(p, emk)| (p.to_string(), matchkey_decrypt.decrypt(*emk)))
            .collect();
        DecryptedMatchkeys::from_matchkeys(decrypted_matchkeys)
    }
}

impl fmt::Debug for EncryptedMatchkeys {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.match_keys)
    }
}

pub struct DecryptedMatchkeys {
    match_keys: HashMap<String, RistrettoPoint>,
}

impl PartialEq for DecryptedMatchkeys {
    fn eq(&self, other: &Self) -> bool {
        any_matches(self.match_keys.values(), &other.match_keys.values())
    }
}

impl DecryptedMatchkeys {
    pub fn count_matches(&self, other: &Self) -> usize {
        n_matches(self.match_keys.values(), &other.match_keys.values())
    }

    pub fn from_matchkeys(match_keys: HashMap<String, RistrettoPoint>) -> DecryptedMatchkeys {
        DecryptedMatchkeys { match_keys }
    }
}

impl fmt::Debug for DecryptedMatchkeys {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.match_keys)
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct EventReport {
    pub encrypted_match_keys: EncryptedMatchkeys,
    //event_generating_biz: String,
    //ad_destination_biz: String,
    //h3_secret_shares: EncryptedSecretShares,
    //h4_secret_shares: EncryptedSecretShares,
    //range_proofs: ,
}

impl EventReport {
    pub fn matchkeys(&self) -> &EncryptedMatchkeys {
        &self.encrypted_match_keys
    }
}

impl fmt::Debug for EventReport {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "encrypted_match_keys: {:?}", self.encrypted_match_keys)
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct DecryptedEventReport {
    pub decrypted_match_keys: DecryptedMatchkeys,
    //event_generating_biz: String,
    //ad_destination_biz: String,
    //h3_secret_shares: EncryptedSecretShares,
    //h4_secret_shares: EncryptedSecretShares,
}

impl DecryptedEventReport {
    pub fn matchkeys(&self) -> &DecryptedMatchkeys {
        &self.decrypted_match_keys
    }
}

impl fmt::Debug for DecryptedEventReport {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "decrypted_match_keys: {:?}", self.decrypted_match_keys)
    }
}

fn n_matches<T>(
    a: impl Iterator<Item = impl PartialEq<T>>,
    b: &(impl Iterator<Item = T> + Clone),
) -> usize {
    a.into_iter()
        .map(|x| b.clone().filter(|y| x.eq(y)).count())
        .sum()
}

fn any_matches<T>(
    a: impl Iterator<Item = impl PartialEq<T>>,
    b: &(impl Iterator<Item = T> + Clone),
) -> bool {
    a.into_iter().any(|x| b.clone().any(|y| x.eq(&y)))
}
