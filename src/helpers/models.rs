use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use std::ops::Range;

// Type aliases to indicate whether the parameter should be encrypted, secret shared, etc.
// Underlying types are temporalily assigned for PoC.
type CipherText = [u8; 32];
type PlainText = String;
type SecretShare = [CipherText; 3];

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
struct Event {
    /// Name of the business entity that generated this event. For source-fanout,
    /// it's the business who promotes ads. For trigger-fanout, it's the business
    /// where a user has made a conversion.
    entity_name: PlainText,

    /// Secret shared and then encrypted match keys.
    matchkey: SecretShare,

    /// Date and time of the event occurence. Secret shared and encrypted.
    timestamp: SecretShare,
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
struct SourceEvent {
    event: Event,

    /// Campaign ID of the ad served to the user.
    campaign_id: PlainText,
}

#[cfg(feature = "debug")]
impl Debug for SourceEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "SourceEvent:\n  matchkey={:?}\n  campaign_id={}",
            &self.event.matchkey, &self.campaign_id
        )
    }
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
struct TriggerEvent {
    event: Event,

    /// Conversion value.
    value: SecretShare,

    /// Zero knowledge proom that the trigger value lies within a specific range
    /// of values. The range is specified in [TriggerFanoutQuery].
    zkp: PlainText,
}

#[cfg(feature = "debug")]
impl Debug for TriggerEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "TriggerEvent:\n  matchkey={:?}\n  value={:?}",
            &self.event.matchkey, &self.value
        )
    }
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
enum QueryType {
    Source,
    Trigger,
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
enum Node {
    Helper1,
    Helper2,
    Helper3,
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
struct Query {
    /// Caller authentication token.
    auth_token: PlainText,

    /// Initial MPC helper node to send the data to.
    leader_node: Node,

    /// List of match key providers to be used by the source and trigger events during an epoch.
    mk_providers: Vec<String>,

    /// Source-fanout or Trigger-fanout.
    query_type: QueryType,

    /// Percentage of epoch-level privacy budget this query should consume.
    privacy_budget: f32,

    /// A collection of source events. At least 100 (TBD) unique source events must be provided.
    source_events: Vec<SourceEvent>,

    /// A collection of trigger events. At least 10 (TBD) unique trigger events must be provided.
    trigger_events: Vec<TriggerEvent>,
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
struct SourceFanoutQuery {
    query: Query,

    /// The maximum number of attributed conversion events that a single person can contribute
    /// towards the final output.
    cap: u32,
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
    query: Query,

    /// The range which all trigger event's conversion values must lie within.
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
