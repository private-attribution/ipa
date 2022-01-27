#[cfg(feature = "enable-serde")]
use crate::error::{Error, Res};
#[cfg(feature = "enable-serde")]
use crate::helpers::Helpers;
use crate::ss::{
    AdditiveShare, DecryptionKey as ShareDecryptionKey, EncryptedSecret,
    EncryptionKey as ShareEncryptionKey,
};
use rand::thread_rng;
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
    Helper1,
    Helper2,
}

/// All of the public information about an aggregation helper.
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct PublicHelper {
    role: Role,

    share_encryption: ShareEncryptionKey,
}

impl PublicHelper {
    #[allow(dead_code)]
    fn share_public_key(&self) -> ShareEncryptionKey {
        self.share_encryption
    }
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct Helper {
    #[cfg_attr(feature = "enable-serde", serde(flatten))]
    public: PublicHelper,

    share_decryption: ShareDecryptionKey,
}

impl Helper {
    #[must_use]
    pub fn new(role: Role) -> Self {
        let share_decryption = ShareDecryptionKey::new(&mut thread_rng());
        Self {
            public: PublicHelper {
                role,
                share_encryption: share_decryption.encryption_key(),
            },
            share_decryption,
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
        fs::write(f, serde_json::to_string(&self.public)?.as_bytes())?;
        let f = Helpers::filename(dir, false);
        fs::write(f, serde_json::to_string(&self)?.as_bytes())?;
        Ok(())
    }

    pub fn sum<'item, const N: u32>(
        self,
        shares: impl IntoIterator<Item = (AdditiveShare<N>, &'item EncryptedSecret)>,
    ) -> AdditiveShare<N> {
        shares
            .into_iter()
            .map(|(share, secret)| {
                let v = self.share_decryption.decryptor(secret).decrypt(share);
                println!("add: {}", v);
                v
            })
            .sum()
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
    use crate::ss::{AdditiveShare, EncryptedSecret};
    use rand::{thread_rng, RngCore};

    fn make_some_values<const N: usize>() -> [u64; N] {
        let mut rng = thread_rng();
        let mut values = [0; N];
        for i in &mut values {
            *i = u64::from(rng.next_u32());
        }
        values
    }

    // This ensures that we get the right mix of values and references from a collection of values.
    fn unref_share<const N: u32>(
        (value, secret): &(AdditiveShare<N>, EncryptedSecret),
    ) -> (AdditiveShare<N>, &EncryptedSecret) {
        (*value, secret)
    }

    #[test]
    fn encrypt_and_aggregate() {
        let values = make_some_values::<100>();
        let expected_total: u64 = values.iter().sum();

        let mut rng = thread_rng();
        let (shares1, shares2): (Vec<_>, Vec<_>) = values
            .iter()
            .map(|&v| AdditiveShare::<64>::share(v, &mut rng))
            .unzip();

        let helper1 = Helper::new(Role::Helper1);
        let helper2 = Helper::new(Role::Helper2);

        let encrypted_shares1: Vec<_> = shares1
            .into_iter()
            .map(|share| {
                let (mut encryptor, secret) = helper1.share_public_key().encryptor(&mut rng);
                (encryptor.encrypt(share), secret)
            })
            .collect();
        let encrypted_shares2: Vec<_> = shares2
            .into_iter()
            .map(|share| {
                let (mut encryptor, secret) = helper2.share_public_key().encryptor(&mut rng);
                (encryptor.encrypt(share), secret)
            })
            .collect();

        let sum1 = helper1.sum(encrypted_shares1.iter().map(unref_share));
        let sum2 = helper2.sum(encrypted_shares2.iter().map(unref_share));

        let total = sum1 + sum2;
        assert_eq!(total.value(), u128::from(expected_total));
    }

    #[test]
    fn encrypt_rerandomize_aggregate() {
        let values = make_some_values::<100>();
        let expected_total: u64 = values.iter().sum();

        let mut rng = thread_rng();
        let (shares1, shares2): (Vec<_>, Vec<_>) = values
            .iter()
            .map(|&v| AdditiveShare::<64>::share(v, &mut rng))
            .unzip();

        let helper1 = Helper::new(Role::Helper1);
        let helper2 = Helper::new(Role::Helper2);

        // In a real deployment these steps wouldn't look quite like this.
        // A client would split the shares and encrypt them to each helper.
        // Then it would send both to the source or trigger helper,
        // which would rerandomize as we do here (adding an offset and re-encrypting the share)
        // That would then send to its peer, which would add its own offset.
        // Then the shares would be separated and sent to the aggregation helpers for decryption.
        // This runs the whole process at once, with a single offset and no shuffle.
        let offset = AdditiveShare::from(rng.next_u64());
        let encrypted_shares1: Vec<_> = shares1
            .into_iter()
            .map(|share| {
                let (mut encryptor, secret) = helper1.share_public_key().encryptor(&mut rng);
                (
                    encryptor.encrypt(share) + offset,
                    secret.rerandomize(helper1.share_public_key(), &mut rng),
                )
            })
            .collect();
        let encrypted_shares2: Vec<_> = shares2
            .into_iter()
            .map(|share| {
                let (mut encryptor, secret) = helper2.share_public_key().encryptor(&mut rng);
                (
                    encryptor.encrypt(share) - offset,
                    secret.rerandomize(helper2.share_public_key(), &mut rng),
                )
            })
            .collect();

        let sum1 = helper1.sum(encrypted_shares1.iter().map(unref_share));
        let sum2 = helper2.sum(encrypted_shares2.iter().map(unref_share));

        let total = sum1 + sum2;
        assert_eq!(total.value(), u128::from(expected_total));
    }
}
