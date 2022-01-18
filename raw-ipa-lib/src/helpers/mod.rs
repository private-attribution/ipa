pub mod aggregation;
pub mod event;

use crate::error::{Error, Res};
use crate::threshold::ThresholdEncryptionKey;
use aggregation::PublicAggregationHelper;
use event::{PublicSourceEventHelper, PublicTriggerEventHelper};
#[cfg(feature = "enable-serde")]
use serde::Deserialize;
use std::fs;
#[cfg(feature = "enable-serde")]
use std::path::{Path, PathBuf};

const PUBLIC_FILE: &str = "public.json";

#[cfg(feature = "enable-serde")]
pub trait HelperLocations {
    fn source_event(&self) -> &Path;
    fn trigger_event(&self) -> &Path;
    fn aggregation1(&self) -> &Path;
    fn aggregation2(&self) -> &Path;
}

/// Public information about all helpers.
#[allow(dead_code)]
pub struct Helpers {
    source_event_helper: PublicSourceEventHelper,
    trigger_event_helper: PublicTriggerEventHelper,
    aggregation_helper1: PublicAggregationHelper,
    aggregation_helper2: PublicAggregationHelper,
    threshold_key: ThresholdEncryptionKey,
}

impl Helpers {
    #[cfg(feature = "enable-serde")]
    fn load_helper<T>(dir: &Path, file: &str) -> Res<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let mut f = PathBuf::from(dir);
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
    pub fn load(locations: &impl HelperLocations) -> Res<Self> {
        let source_event_helper: PublicSourceEventHelper =
            Self::load_helper(locations.source_event(), PUBLIC_FILE)?;
        let trigger_event_helper: PublicTriggerEventHelper =
            Self::load_helper(locations.trigger_event(), PUBLIC_FILE)?;
        let threshold_key = ThresholdEncryptionKey::new(
            source_event_helper.matchkey_encryption_key(),
            trigger_event_helper.matchkey_encryption_key(),
        );
        let v = Self {
            source_event_helper,
            trigger_event_helper,
            aggregation_helper1: Self::load_helper(locations.aggregation1(), PUBLIC_FILE)?,
            aggregation_helper2: Self::load_helper(locations.aggregation2(), PUBLIC_FILE)?,
            threshold_key,
        };
        Ok(v)
    }

    #[must_use]
    pub fn matchkey_encryption_key(&self) -> ThresholdEncryptionKey {
        self.threshold_key
    }
}
