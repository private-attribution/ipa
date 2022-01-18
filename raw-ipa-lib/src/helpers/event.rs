use crate::threshold::ThresholdDecryptionKey;
use rust_elgamal::EncryptionKey;
#[cfg(feature = "enable-serde")]
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct PublicSourceEventHelper {
    matchkey_encrypt: EncryptionKey,
}

impl PublicSourceEventHelper {
    #[must_use]
    pub fn matchkey_encryption_key(&self) -> EncryptionKey {
        self.matchkey_encrypt
    }
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct SourceEventHelper {
    #[cfg_attr(feature = "enable-serde", serde(flatten))]
    public: PublicSourceEventHelper,

    matchkey_decrypt: ThresholdDecryptionKey,
}

impl SourceEventHelper {
    // TODO work out how to locate all the necessary files.
    // const DIR: &'static str = "SourceEventHelper";
}

impl Deref for SourceEventHelper {
    type Target = PublicSourceEventHelper;
    fn deref(&self) -> &Self::Target {
        &self.public
    }
}
impl DerefMut for SourceEventHelper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.public
    }
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct PublicTriggerEventHelper {
    matchkey_encrypt: EncryptionKey,
}

impl PublicTriggerEventHelper {
    #[must_use]
    pub fn matchkey_encryption_key(&self) -> EncryptionKey {
        self.matchkey_encrypt
    }
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct TriggerEventHelper {
    #[serde(flatten)]
    public: PublicTriggerEventHelper,

    matchkey_decrypt: ThresholdDecryptionKey,
}

impl Deref for TriggerEventHelper {
    type Target = PublicTriggerEventHelper;
    fn deref(&self) -> &Self::Target {
        &self.public
    }
}
impl DerefMut for TriggerEventHelper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.public
    }
}
