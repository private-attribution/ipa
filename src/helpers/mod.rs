pub mod error;
pub mod models;
pub mod ring;
mod mesh;

/// Represents a unique identity of each helper running MPC computation.
#[derive(Copy, Clone, Debug, PartialEq, Hash, Eq)]
pub enum Identity {
    H1,
    H2,
    H3,
}

pub enum Direction {
    Left,
    Right
}

impl Identity {
    pub fn all_variants() -> &'static [Identity; 3] {
        static VARIANTS: &'static [Identity; 3] = &[Identity::H1, Identity::H2, Identity::H3];

        VARIANTS
    }

    pub fn peer(&self, direction: Direction) -> Identity {
        let len = Identity::all_variants().len() as i32;
        let my_idx = Identity::all_variants()
            .iter()
            .position(|lhs| lhs == self)
            .unwrap() as i32;

        let peer_idx = my_idx + match direction {
            Direction::Left => -1,
            Direction::Right => 1
        };
        let peer_idx = (peer_idx % len + len) % len;

        Identity::all_variants()[peer_idx as usize]
    }
}


#[cfg(test)]
mod tests {
    mod identity_tests {
        use crate::helpers::{Direction, Identity};

        #[test]
        pub fn peer_works() {
            assert_eq!(Identity::H1.peer(Direction::Left), Identity::H3);
            assert_eq!(Identity::H1.peer(Direction::Right), Identity::H2);
            assert_eq!(Identity::H3.peer(Direction::Left), Identity::H2);
            assert_eq!(Identity::H3.peer(Direction::Right), Identity::H1);
            assert_eq!(Identity::H2.peer(Direction::Left), Identity::H1);
            assert_eq!(Identity::H2.peer(Direction::Right), Identity::H3);
        }
    }
}

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
