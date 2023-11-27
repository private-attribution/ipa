use std::{
    fmt::{Debug, Formatter},
    io::{Error as IoError, ErrorKind as IoErrorKind},
    ops::Range,
};

use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};

// Type aliases to indicate whether the parameter should be encrypted, secret shared, etc.
// Underlying types are temporalily assigned for PoC.
pub type CipherText = Vec<u8>;
type PlainText = String;
pub type MatchKey = u64;
pub type Number = u32;

/// An epoch in which this event is generated. Using an 8-bit value = 256 epochs > 4 years (assuming 1 epoch = 1 week).
pub type Epoch = u8;

/// An offset in seconds into a given epoch. Using an 32-bit value > 20-bit > 604,800 seconds.
pub type Offset = u32;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct SecretShare {
    ss: [CipherText; 3],
}

impl SecretShare {
    fn combine(&self) -> Vec<u8> {
        let mut result = Vec::new();

        assert!(self.ss[0].len() == self.ss[1].len());
        assert!(self.ss[0].len() == self.ss[2].len());

        for i in 0..self.ss[0].len() {
            result.push(self.ss[0][i] ^ self.ss[1][i] ^ self.ss[2][i]);
        }

        result
    }

    // TODO: Add Shamir's SS

    fn xor<R: RngCore + CryptoRng>(data: &[u8], rng: &mut R) -> Self {
        let mut ss = [Vec::new(), Vec::new(), Vec::new()];

        for x in data {
            let ss1 = rng.gen::<u8>();
            let ss2 = rng.gen::<u8>();
            let ss3 = ss1 ^ ss2 ^ x;

            ss[0].push(ss1);
            ss[1].push(ss2);
            ss[2].push(ss3);
        }

        SecretShare { ss }
    }
}

pub trait SecretSharable {
    /// Splits the number into secret shares
    fn xor_split<R: RngCore + CryptoRng>(&self, rng: &mut R) -> SecretShare;

    /// Combines the given secret shares back to [Self]
    /// # Errors
    /// if the combined data overflows [Self]
    fn combine(data: &SecretShare) -> Result<Self, IoError>
    where
        Self: Sized;
}

impl SecretSharable for u32 {
    fn xor_split<R: RngCore + CryptoRng>(&self, rng: &mut R) -> SecretShare {
        SecretShare::xor(&self.to_be_bytes(), rng)
    }

    fn combine(data: &SecretShare) -> Result<Self, IoError> {
        let ss = data.combine();

        let mut high = ss[0..ss.len() - 4].to_vec();
        high.retain(|x| *x != 0);

        if ss.len() > 4 && !high.is_empty() {
            return Err(IoError::from(IoErrorKind::InvalidData));
        }

        let mut bytes = [0u8; 4];
        for (i, v) in ss[ss.len() - 4..].iter().enumerate() {
            bytes[i] = *v;
        }

        Ok(u32::from_be_bytes(bytes))
    }
}

impl SecretSharable for u64 {
    fn xor_split<R: RngCore + CryptoRng>(&self, rng: &mut R) -> SecretShare {
        SecretShare::xor(&self.to_be_bytes(), rng)
    }

    fn combine(data: &SecretShare) -> Result<Self, IoError> {
        let ss = data.combine();

        let mut high = ss[0..ss.len() - 8].to_vec();
        high.retain(|x| *x != 0);

        if ss.len() > 8 && !high.is_empty() {
            return Err(IoError::from(IoErrorKind::InvalidData));
        }

        let mut bytes = [0u8; 8];
        for (i, v) in ss[ss.len() - 8..].iter().enumerate() {
            bytes[i] = *v;
        }

        Ok(u64::from_be_bytes(bytes))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
/// A timestamp of a source/trigger report represented by epoch and offset.
///
/// Internally, the time is stored in `u32`, but the value is capped at `(Epoch::MAX + 1) * SECONDS_IN_EPOCH - 1`.
/// The top limit is ensured when this instance is created with `new`. See `new` for more.
///
/// For now, we assume `epoch` is `u8` and 1 epoch = 1 week. Therefore, we only need 8 bits for `epoch` and 20 bits for
/// `offset` (`log2(SECONDS_IN_EPOCH)` < 20) out of `u32`. Since the internal value is capped, we can safely assume that
/// 4 MSBs are always 0.
pub struct EventTimestamp(u32);

impl EventTimestamp {
    /// Number of days in an epoch.
    pub const DAYS_IN_EPOCH: Epoch = 7;

    /// Number of seconds in an epoch.
    pub const SECONDS_IN_EPOCH: u32 = Self::DAYS_IN_EPOCH as u32 * 86_400;

    /// Creates a new instance of `EventTimestamp` with the given `epoch` and `offset`.
    ///
    /// An epoch is a set period of time in days, which is defined as `EventTimestamp::DAYS_IN_EPOCH`.
    ///
    /// An offset is the time difference in seconds into a given epoch. Its max value is defined as
    /// `EventTimestamp::SECONDS_IN_EPOCH`.
    ///
    /// The type of `offset` parameter is `u32`, but its upper bound is capped at `EventTimestamp::SECONDS_IN_EPOCH - 1`.
    /// Any `offset` value larger than `EventTimestamp::SECONDS_IN_EPOCH` will be truncated. In other words, `offset`
    /// overflow will simply wrap, and has no effect on `epoch` value.
    pub fn new(epoch: Epoch, offset: Offset) -> Self {
        Self(u32::from(epoch) * Self::SECONDS_IN_EPOCH + (offset % Self::SECONDS_IN_EPOCH))
    }

    /// An epoch in which this event is generated. Using an 8-bit value = 256 epochs > 4 years (assuming 1 epoch = 1 week).
    ///
    /// How we send an epoch epoch value between Report Collector and Helper network is still an open question. We will
    /// either send it in the clear, or mix it in MAC. For now, we can assume that this struct is a MPC internal data
    /// model.
    #[allow(clippy::cast_possible_truncation)]
    pub fn epoch(self) -> Epoch {
        (self.0 / Self::SECONDS_IN_EPOCH) as Epoch
    }

    /// An offset in seconds into a given epoch. Max value is `SECONDS_IN_EPOCH - 1`.
    ///
    /// Use `u32` (`< 2^20 seconds`) to leverage simple arithmetics, but we drop the first 12 bits when serializing.
    /// That'll save us ~1.5G with 1B rows.
    pub fn offset(self) -> Offset {
        (self.0 % Self::SECONDS_IN_EPOCH) as Offset
    }
}

/// Converts seconds into `EventTimestamp`. Any value larger than the maximum value of `EventTimestamp` will wrap.
#[allow(clippy::cast_possible_truncation)]
impl From<u64> for EventTimestamp {
    fn from(v: u64) -> Self {
        let seconds_in_epoch = u64::from(EventTimestamp::SECONDS_IN_EPOCH);

        // being explicit here to indicate that overflow will wrap
        let epoch = (v / seconds_in_epoch % (u64::from(Epoch::MAX) + 1)) as Epoch;
        let offset = (v % seconds_in_epoch) as u32;

        EventTimestamp::new(epoch, offset)
    }
}

/// Converts seconds into `EventTimestamp`. Any value larger than the maximum value of `EventTimestamp` will wrap.
impl From<u32> for EventTimestamp {
    fn from(v: u32) -> Self {
        EventTimestamp::from(u64::from(v))
    }
}

impl PartialOrd for EventTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(u32::from(*self).cmp(&u32::from(*other)))
    }
}

/// Converts `EventTimestamp` to `u32` in seconds. The return value is guaranteed to be less than
/// `(Epoch::MAX + 1) * EventTimestamp::SECONDS_IN_EPOCH`.
impl From<EventTimestamp> for u32 {
    fn from(v: EventTimestamp) -> Self {
        v.0
    }
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct Event {
    // An identifier, set in the user agent, which identifies an individual person. This must never be released (beyond
    /// the match key provider) to any party in unencrypted form. For the purpose of this tool, however, the value is in
    /// clear and not secret shared.
    pub matchkey: MatchKey,

    /// An identifier, specified by the report collector, to denote if a given pair of source and trigger events can be
    /// attributed (beyond having the same match key.) If None, a trigger event will be attributed to all source events.
    pub attribution_constraint_id: Option<Number>,

    /// A timestamp in which this event is generated.
    pub timestamp: EventTimestamp,
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub enum GenericReport {
    /// An event produced on websites/apps when a user interacts with an ad (i.e. impression, click).
    Source {
        event: Event,

        /// A key, specified by the report collector, which allows for producing aggregates across many groups (or breakdowns.)
        breakdown_key: Number,
    },

    /// An event produced on websites/apps when a user takes an action (i.e. product view, purchase).
    Trigger {
        event: Event,

        /// The value of the trigger report to be aggregated.
        value: Number,
    },
}

// TODO(taiki): Implement Serialize/Deserialize

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
enum QueryType {
    SourceFanout,
    TriggerFanout,
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
enum Node {
    Helper1,
    Helper2,
    Helper3,
}

#[cfg_attr(feature = "enable-serde", derive(Serialize))]
struct IPAQuery {
    /// Caller authentication token.
    auth_token: PlainText,

    /// Initial MPC helper node to send the data to.
    leader_node: Node,

    /// List of match key providers to be used by the source and trigger events during an epoch.
    mk_providers: Vec<String>,

    /// Source-fanout or Trigger-fanout.
    query_type: QueryType,

    /// Percentage of epoch-level privacy budget this query should consume. Likely 1-100.
    privacy_budget: u8,

    /// A collection of source events. At least 100 (TBD) unique source events must be provided.
    reports: Vec<GenericReport>,
}

#[cfg_attr(feature = "enable-serde", derive(Serialize))]
struct SourceFanoutQuery {
    query: IPAQuery,

    /// The maximum number of attributed conversion events that a single person can contribute
    /// towards the final output. We could also express this using sum of trigger values.
    /// We'll leave it for the future spec to decide.
    cap: u8,
}

#[cfg(feature = "debug")]
impl Debug for SourceFanoutQuery {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "SourceFanoutQuery:\n  {} events",
            &self.query.reports.len(),
        )
    }
}

#[cfg_attr(feature = "enable-serde", derive(Serialize))]
struct TriggerFanoutQuery {
    query: IPAQuery,

    /// The range within which all the trigger event values must lie.
    value_range: Range<u32>,
}

impl Debug for TriggerFanoutQuery {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "TriggerFanoutQuery:\n  {} events",
            &self.query.reports.len(),
        )
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use super::EventTimestamp;
    use crate::models::Epoch;

    #[test]
    fn event_timestamp_new() {
        let t = EventTimestamp::new(0, 1);
        assert_eq!(0, t.epoch());
        assert_eq!(1, t.offset());
        assert_eq!(1, u32::from(t));

        let t = EventTimestamp::new(1, EventTimestamp::SECONDS_IN_EPOCH - 1);
        assert_eq!(1, t.epoch());
        assert_eq!(EventTimestamp::SECONDS_IN_EPOCH - 1, t.offset());
        assert_eq!(EventTimestamp::SECONDS_IN_EPOCH * 2 - 1, u32::from(t));

        let t = EventTimestamp::new(0, EventTimestamp::SECONDS_IN_EPOCH);
        assert_eq!(0, t.epoch());
        assert_eq!(0, t.offset());
        assert_eq!(0, u32::from(t));

        let t = EventTimestamp::new(0, EventTimestamp::SECONDS_IN_EPOCH + 1);
        assert_eq!(0, t.epoch());
        assert_eq!(1, t.offset());
        assert_eq!(1, u32::from(t));
    }

    #[test]
    fn event_timestamp_from() {
        // 256 epochs - 1 sec
        let event_timestamp_internal_max =
            (u32::from(Epoch::MAX) + 1) * EventTimestamp::SECONDS_IN_EPOCH - 1;

        let ts = EventTimestamp::from(0_u32);
        assert_eq!(ts.epoch(), 0);
        assert_eq!(ts.offset(), 0);

        let ts = EventTimestamp::from(EventTimestamp::SECONDS_IN_EPOCH);
        assert_eq!(ts.epoch(), 1);
        assert_eq!(ts.offset(), 0);

        let ts = EventTimestamp::from(event_timestamp_internal_max);
        assert_eq!(ts.epoch(), Epoch::MAX);
        assert_eq!(ts.offset(), EventTimestamp::SECONDS_IN_EPOCH - 1);

        let ts = EventTimestamp::from(event_timestamp_internal_max + 1);
        assert_eq!(ts.epoch(), 0);
        assert_eq!(ts.offset(), 0);

        let ts = EventTimestamp::from(u32::MAX);
        assert_eq!(ts.epoch(), 189);
        assert_eq!(ts.offset(), 282_495);

        // `u32::MAX + 1` (internal type overflow) doesn't cause `epoch` and `offset` wrap
        let ts = EventTimestamp::from(u64::from(u32::MAX) + 1);
        assert_eq!(ts.epoch(), 189);
        assert_eq!(ts.offset(), 282_496);
    }

    #[test]
    fn event_timestamp_cmp() {
        let zero = EventTimestamp::new(0, 0);

        assert!(zero == zero);
        assert!(zero < EventTimestamp::new(0, 1));
        assert!(EventTimestamp::new(1, 0) > EventTimestamp::new(0, 1));
        assert!(zero == EventTimestamp::new(0, EventTimestamp::SECONDS_IN_EPOCH));
    }
}
