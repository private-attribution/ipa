use std::fmt::Debug;

use serde::{Deserialize, Serialize};

// Type aliases to indicate whether the parameter should be encrypted, secret shared, etc.
// Underlying types are temporalily assigned for PoC.
pub type MatchKey = u64;
pub type Number = u32;

/// An epoch in which this event is generated. Using an 8-bit value = 256 epochs > 4 years (assuming 1 epoch = 1 week).
pub type Epoch = u8;

/// An offset in seconds into a given epoch. Using an 32-bit value > 20-bit > 604,800 seconds.
pub type Offset = u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
enum QueryType {
    SourceFanout,
    TriggerFanout,
}

#[derive(Serialize, Deserialize)]
enum Node {
    Helper1,
    Helper2,
    Helper3,
}

#[cfg(all(test, unit_test))]
mod tests {
    use super::{Epoch, EventTimestamp};

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
