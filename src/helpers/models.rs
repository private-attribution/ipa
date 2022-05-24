use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use std::ops::Range;

// Type aliases to indicate whether the parameter should be encrypted, secret shared, etc.
// Underlying types are temporalily assigned for PoC.
type CipherText = Vec<u8>;
type PlainText = String;
type SecretShare = [CipherText; 3];

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
struct Event {
    /// Secret shared and then encrypted match keys.
    matchkeys: Vec<SecretShare>,

    /// The epoch which this event is generated. Using an 8-bit value = 256 epochs > 4 years (assuming 1 epoch = 1 week).
    /// This field is in the clear.
    epoch: u8,

    /// An offset in seconds into a given offset. The clear is u32 (< 2^20 seconds), then encrypted and secret shared.
    timestamp: SecretShare,
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
struct SourceEvent {
    event: Event,

    /// A key to group sets of the events.
    breakdown_key: PlainText,
}

#[cfg(feature = "debug")]
impl Debug for SourceEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "SourceEvent:\n  matchkeys={:?}\n  breakdown_key={}",
            &self.event.matchkeys, &self.breakdown_key
        )
    }
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
struct TriggerEvent {
    event: Event,

    /// Conversion value.
    value: SecretShare,

    /// Zero knowledge proof that the trigger value lies within a specific range
    /// of values. The range is specified in [TriggerFanoutQuery].
    zkp: PlainText,
}

#[cfg(feature = "debug")]
impl Debug for TriggerEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "TriggerEvent:\n  matchkeys={:?}\n  value={:?}",
            &self.event.matchkeys, &self.value
        )
    }
}

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

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
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
    source_events: Vec<SourceEvent>,

    /// A collection of trigger events. At least 10 (TBD) unique trigger events must be provided.
    trigger_events: Vec<TriggerEvent>,
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
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
            "SourceFanoutQuery:\n  {} source events\n  {} trigger events",
            &self.query.source_events.len(),
            &self.query.trigger_events.len()
        )
    }
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
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
            "TriggerFanoutQuery:\n  {} source events\n  {} trigger events",
            &self.query.source_events.len(),
            &self.query.trigger_events.len()
        )
    }
}
