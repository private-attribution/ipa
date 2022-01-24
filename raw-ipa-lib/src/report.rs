use crate::threshold::{Ciphertext, RistrettoPoint};
use std::collections::HashMap;

pub struct EventReport {
    pub encrypted_match_keys: HashMap<String, Ciphertext>,
    //event_generating_biz: String,
    //ad_destination_biz: String,
    //h3_secret_shares: EncryptedSecretShares,
    //h4_secret_shares: EncryptedSecretShares,
    //range_proofs: ,
}

pub struct DecryptedEventReport {
    pub decrypted_match_keys: HashMap<String, RistrettoPoint>,
    //event_generating_biz: String,
    //ad_destination_biz: String,
    //h3_secret_shares: EncryptedSecretShares,
    //h4_secret_shares: EncryptedSecretShares,
}

fn n_matches<T>(
    a: impl Iterator<Item = impl PartialEq<T>>,
    b: impl Iterator<Item = T> + Clone,
) -> usize {
    let b = b.into_iter();
    a.into_iter()
        .map(|x| b.clone().filter(|y| x.eq(y)).count())
        .sum()
}

impl PartialEq for EventReport {
    fn eq(&self, other: &Self) -> bool {
        n_matches(
            self.encrypted_match_keys.values(),
            other.encrypted_match_keys.values(),
        ) > 0
    }

    fn ne(&self, other: &Self) -> bool {
        n_matches(
            self.encrypted_match_keys.values(),
            other.encrypted_match_keys.values(),
        ) == 0
    }
}

impl PartialEq for DecryptedEventReport {
    fn eq(&self, other: &Self) -> bool {
        n_matches(
            self.decrypted_match_keys.values(),
            other.decrypted_match_keys.values(),
        ) > 0
    }

    fn ne(&self, other: &Self) -> bool {
        n_matches(
            self.decrypted_match_keys.values(),
            other.decrypted_match_keys.values(),
        ) == 0
    }
}
