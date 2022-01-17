use crate::error::{Error, Res};
use crate::threshold::{ThresholdDecryptionKey, ThresholdEncryptionKey};
use rust_elgamal::EncryptionKey;
#[cfg(feature = "enable-serde")]
use serde::{Deserialize, Serialize};
use std::fs;
#[cfg(feature = "enable-serde")]
use std::path::{Path, PathBuf};

const PUBLIC_FILE: &str = "public.json";

// TODO - these helper structs all need better names...
// ... and their own files, probably

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct PublicHelper1 {
    matchkey_encrypt: EncryptionKey,
}

impl PublicHelper1 {
    #[must_use]
    pub fn matchkey_encryption_key(&self) -> EncryptionKey {
        self.matchkey_encrypt
    }
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct Helper1 {
    #[cfg_attr(feature = "enable-serde", serde(flatten))]
    public: PublicHelper1,

    matchkey_decrypt: ThresholdDecryptionKey,
}

impl Helper1 {
    // TODO work out how to locate all the necessary files.
    // const DIR: &'static str = "helper1";
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct PublicHelper2 {
    matchkey_encrypt: EncryptionKey,
}

impl PublicHelper2 {
    #[must_use]
    pub fn matchkey_encryption_key(&self) -> EncryptionKey {
        self.matchkey_encrypt
    }
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct Helper2 {
    #[serde(flatten)]
    public: PublicHelper2,

    matchkey_decrypt: ThresholdDecryptionKey,
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct PublicHelper3 {}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct Helper3 {
    #[serde(flatten)]
    public: PublicHelper3,
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct PublicHelper4 {}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct Helper4 {
    #[serde(flatten)]
    public: PublicHelper4,
}

/// Public information about all helpers.
#[allow(dead_code)]
pub struct Helpers {
    helper1: PublicHelper1,
    helper2: PublicHelper2,
    helper3: PublicHelper3,
    helper4: PublicHelper4,
    threshold_key: ThresholdEncryptionKey,
}

impl Helpers {
    #[cfg(feature = "enable-serde")]
    fn load_helper<'a, T>(dir: Option<impl AsRef<Path>>, file: &str) -> Res<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let d = dir.ok_or(Error::NotEnoughHelpers)?;
        let mut f = PathBuf::from(d.as_ref());
        if !f.is_dir() || !f.exists() {
            return Err(Error::NotFound);
        }
        f.push(file);
        let s = fs::read_to_string(f)?;
        Ok(serde_json::from_str(&s)?)
    }

    /// # Errors
    /// If JSON files are missing or badly formatted.
    #[cfg(feature = "enable-serde")]
    pub fn load(helper_dirs: impl IntoIterator<Item = impl AsRef<Path>>) -> Res<Self> {
        let mut dirs = helper_dirs.into_iter();
        let helper1: PublicHelper1 = Self::load_helper(dirs.next(), PUBLIC_FILE)?;
        let helper2: PublicHelper2 = Self::load_helper(dirs.next(), PUBLIC_FILE)?;
        let threshold_key = ThresholdEncryptionKey::new(
            helper1.matchkey_encryption_key(),
            helper2.matchkey_encryption_key(),
        );
        let v = Self {
            helper1,
            helper2,
            helper3: Self::load_helper(dirs.next(), PUBLIC_FILE)?,
            helper4: Self::load_helper(dirs.next(), PUBLIC_FILE)?,
            threshold_key,
        };
        if dirs.next().is_some() {
            return Err(Error::TooManyHelpers);
        }
        Ok(v)
    }

    #[must_use]
    pub fn matchkey_encryption_key(&self) -> ThresholdEncryptionKey {
        self.threshold_key
    }
}
