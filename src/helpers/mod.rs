pub mod aggregation;
pub mod error;
pub mod event;
pub mod models;
pub mod privacy_budget;
pub mod ring;

pub use aggregation::{
    Helper as AggregationHelper, PublicHelper as PublicAggregationHelper,
    Role as AggregationHelperRole,
};
pub use event::{
    Helper as EventHelper, PublicHelper as PublicEventHelper, Role as EventHelperRole,
};

#[cfg(feature = "enable-serde")]
use crate::error::{Error, Res};
use crate::threshold::EncryptionKey as ThresholdEncryptionKey;
#[cfg(feature = "enable-serde")]
use serde::Deserialize;
use std::fmt::{Debug, Display, Error as FmtError, Formatter};
#[cfg(feature = "enable-serde")]
use std::fs;
#[cfg(feature = "enable-serde")]
use std::ops::Index;
#[cfg(feature = "enable-serde")]
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug)]
pub struct HelperRoleUnknown(String);

impl Display for HelperRoleUnknown {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        f.write_str("unknown helper type: ")?;
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Event(EventHelperRole),
    Aggregation(AggregationHelperRole),
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Self::Event(EventHelperRole::Source) => "SourceEventHelper",
            Self::Event(EventHelperRole::Trigger) => "TriggerEventHelper",
            Self::Aggregation(AggregationHelperRole::Helper1) => "AggregationHelper1",
            Self::Aggregation(AggregationHelperRole::Helper2) => "AggregationHelper2",
        }
    }
}

impl FromStr for Role {
    type Err = HelperRoleUnknown;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_ascii_lowercase();
        match s.as_str() {
            "sourceeventhelper" | "seh" => Ok(Self::Event(EventHelperRole::Source)),
            "triggereventhelper" | "teh" => Ok(Self::Event(EventHelperRole::Trigger)),
            "aggregationhelper1" | "ah1" => Ok(Self::Aggregation(AggregationHelperRole::Helper1)),
            "aggregationhelper2" | "ah2" => Ok(Self::Aggregation(AggregationHelperRole::Helper2)),
            _ => Err(HelperRoleUnknown(s)),
        }
    }
}

impl Display for Role {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        f.write_str(self.as_str())
    }
}

#[cfg(feature = "enable-serde")]
pub trait HelperLocations: Index<Role> {
    fn source_event(&self) -> &Path;
    fn trigger_event(&self) -> &Path;
    fn aggregation1(&self) -> &Path;
    fn aggregation2(&self) -> &Path;
}

/// Public information about all helpers.
#[allow(dead_code)]
pub struct Helpers {
    source_event_helper: PublicEventHelper,
    trigger_event_helper: PublicEventHelper,
    aggregation_helper1: PublicAggregationHelper,
    aggregation_helper2: PublicAggregationHelper,
    threshold_key: ThresholdEncryptionKey,
}

impl Helpers {
    #[cfg(feature = "enable-serde")]
    const HELPER_PUBLIC_JSON: &'static str = "public.json";
    #[cfg(feature = "enable-serde")]
    const HELPER_PRIVATE_JSON: &'static str = "private.json";

    #[cfg(feature = "enable-serde")]
    #[must_use]
    pub fn filename(dir: &Path, public: bool) -> PathBuf {
        let mut f = PathBuf::from(dir);
        f.push(if public {
            Self::HELPER_PUBLIC_JSON
        } else {
            Self::HELPER_PRIVATE_JSON
        });
        f
    }

    #[cfg(feature = "enable-serde")]
    fn load_public<T>(dir: &Path) -> Res<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let f = Self::filename(dir, true);
        if !f.is_file() {
            return Err(Error::NotFound);
        }
        let s = fs::read_to_string(f)?;
        Ok(serde_json::from_str(&s)?)
    }

    /// # Errors
    /// If JSON files are missing or badly formatted.
    #[cfg(feature = "enable-serde")]
    pub fn load(locations: &impl HelperLocations) -> Res<Self> {
        let source_event_helper: PublicEventHelper = Self::load_public(locations.source_event())?;
        let trigger_event_helper: PublicEventHelper = Self::load_public(locations.trigger_event())?;
        let threshold_key = ThresholdEncryptionKey::new(&[
            source_event_helper.matchkey_encryption_key(),
            trigger_event_helper.matchkey_encryption_key(),
        ]);
        let v = Self {
            source_event_helper,
            trigger_event_helper,
            aggregation_helper1: Self::load_public(locations.aggregation1())?,
            aggregation_helper2: Self::load_public(locations.aggregation2())?,
            threshold_key,
        };
        Ok(v)
    }

    #[must_use]
    pub fn matchkey_encryption_key(&self) -> ThresholdEncryptionKey {
        self.threshold_key
    }
}
