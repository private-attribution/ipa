use rand::{CryptoRng, Rng, RngCore};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::ops::{Add, AddAssign, Range};

// Type aliases to indicate whether the parameter should be encrypted, secret shared, etc.
// Underlying types are temporalily assigned for PoC.
pub type CipherText = Vec<u8>;
type PlainText = String;
pub type MatchKey = u64;
pub type Number = u32;

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

pub trait EpochDuration: Sized + Add<Output = Self> + AddAssign + PartialOrd + From<u64> {
    type Epoch;
    type Offset;

    const DAYS_IN_EPOCH: Self::Epoch;
    const SECONDS_IN_EPOCH: u64;
    const MAX: u64;

    fn epoch(&self) -> Self::Epoch;
    fn offset(&self) -> Self::Offset;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventTimestamp(u64);

impl EpochDuration for EventTimestamp {
    /// An epoch in which this event is generated. Using an 8-bit value = 256 epochs > 4 years (assuming 1 epoch = 1 week).
    type Epoch = u8;

    /// An offset in seconds into a given epoch. Using an 32-bit value > 20-bit > 604,800 seconds.
    type Offset = u32;

    /// Number of days in an epoch.
    const DAYS_IN_EPOCH: Self::Epoch = 7;

    /// Number of seconds in an eopch.
    const SECONDS_IN_EPOCH: u64 = Self::DAYS_IN_EPOCH as u64 * 86_400;

    /// The largest value that can be represented by this type.
    const MAX: u64 = Self::Epoch::MAX as u64 * Self::SECONDS_IN_EPOCH + Self::SECONDS_IN_EPOCH - 1;

    /// An epoch in which this event is generated. Using an 8-bit value = 256 epochs > 4 years (assuming 1 epoch = 1 week).
    ///
    /// How we send an epoch epoch value between Report Collector and Helper network is still an open question. We will
    /// either send it in the clear, or mix it in MAC. For now, we can assume that this struct is a MPC internal data
    /// model.
    #[allow(clippy::cast_possible_truncation)]
    fn epoch(&self) -> Self::Epoch {
        (self.0 / Self::SECONDS_IN_EPOCH) as Self::Epoch
    }

    /// An offset in seconds into a given epoch. Max value is `SECONDS_IN_EPOCH - 1`.
    ///
    /// Use `u32` (`< 2^20 seconds`) to leverage simple arithmetics, but we drop the first 12 bits when serializing.
    /// That'll save us ~1.5G with 1B rows.
    fn offset(&self) -> Self::Offset {
        (self.0 % Self::SECONDS_IN_EPOCH) as Self::Offset
    }
}

impl From<u64> for EventTimestamp {
    fn from(v: u64) -> Self {
        EventTimestamp(v)
    }
}

impl From<<Self as EpochDuration>::Epoch> for EventTimestamp {
    fn from(v: <Self as EpochDuration>::Epoch) -> Self {
        EventTimestamp(u64::from(v) * Self::SECONDS_IN_EPOCH)
    }
}

impl Add for EventTimestamp {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        EventTimestamp(self.0 + rhs.0)
    }
}

impl AddAssign for EventTimestamp {
    // #[allow(clippy::assign_op_pattern)]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl PartialOrd for EventTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(u64::from(*self).cmp(&u64::from(*other)))
    }
}

impl From<EventTimestamp> for u64 {
    fn from(v: EventTimestamp) -> Self {
        v.0 % (EventTimestamp::MAX + 1)
    }
}

#[derive(Clone, Copy, Debug)]
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

/// Serialize trigger and source reports to the same format. This prevents information leakage by ensuring the helper
/// parties are unable to differentiate between source and trigger reports throughout the entire protocol.
impl Serialize for GenericReport {
    // TODO: In production, fields in GenericReport will be encrypted and secret shared.

    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            GenericReport::Source {
                event,
                breakdown_key,
            } => {
                let mut state = serializer.serialize_struct("GenericReport", 7)?;
                state.serialize_field("matchkey", &event.matchkey)?;
                state.serialize_field(
                    "attribution_constraint_id",
                    &event.attribution_constraint_id,
                )?;
                state.serialize_field("epoch", &event.timestamp.epoch())?;
                state.serialize_field("offset", &event.timestamp.offset())?;
                state.serialize_field("is_trigger_report", &false)?;
                state.serialize_field("breakdown_key", &breakdown_key)?;
                state.serialize_field("value", &0)?;
                state.end()
            }

            GenericReport::Trigger { event, value } => {
                let mut state = serializer.serialize_struct("GenericReport", 7)?;
                state.serialize_field("matchkey", &event.matchkey)?;
                state.serialize_field(
                    "attribution_constraint_id",
                    &event.attribution_constraint_id,
                )?;
                state.serialize_field("epoch", &event.timestamp.epoch())?;
                state.serialize_field("offset", &event.timestamp.offset())?;
                state.serialize_field("is_trigger_report", &true)?;
                state.serialize_field("breakdown_key", &0)?;
                state.serialize_field("value", &value)?;
                state.end()
            }
        }
    }
}

// TODO(taiki): Implement deserializer

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

#[cfg(feature = "debug")]
impl Debug for TriggerFanoutQuery {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "TriggerFanoutQuery:\n  {} events",
            &self.query.reports.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{EpochDuration, EventTimestamp};

    #[test]
    fn event_timestamp() {
        let t = EventTimestamp(1);
        assert_eq!(0, t.epoch());
        assert_eq!(1, t.offset());
        assert_eq!(1, u64::from(t));

        let t = EventTimestamp(EventTimestamp::SECONDS_IN_EPOCH - 1);
        assert_eq!(0, t.epoch());
        assert_eq!(EventTimestamp::SECONDS_IN_EPOCH - 1, u64::from(t.offset()));
        assert_eq!(EventTimestamp::SECONDS_IN_EPOCH - 1, u64::from(t));

        // Epoch carry
        let t = EventTimestamp(EventTimestamp::SECONDS_IN_EPOCH);
        assert_eq!(1, t.epoch());
        assert_eq!(0, t.offset());
        assert_eq!(EventTimestamp::SECONDS_IN_EPOCH, u64::from(t));

        // Epoch carry with addition
        let t = EventTimestamp(EventTimestamp::SECONDS_IN_EPOCH - 1) + EventTimestamp(1);
        assert_eq!(1, t.epoch());
        assert_eq!(0, t.offset());
        assert_eq!(EventTimestamp::SECONDS_IN_EPOCH, u64::from(t));

        let mut t = EventTimestamp(EventTimestamp::MAX);
        assert_eq!(u8::MAX, t.epoch());
        assert_eq!(EventTimestamp::SECONDS_IN_EPOCH - 1, u64::from(t.offset()));
        assert_eq!(EventTimestamp::MAX, u64::from(t));

        // Overflow doesn't panic. Just rolls to 0.
        t += EventTimestamp(1);
        assert_eq!(0, t.epoch());
        assert_eq!(0, u64::from(t.offset()));
        assert_eq!(0, u64::from(t));

        assert_eq!(EventTimestamp(0), EventTimestamp(0));
        assert!(EventTimestamp(0) < EventTimestamp(1));
        assert!(EventTimestamp(EventTimestamp::MAX + 1) < EventTimestamp(EventTimestamp::MAX));
    }
}
