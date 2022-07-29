use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::ops::Range;

// Type aliases to indicate whether the parameter should be encrypted, secret shared, etc.
// Underlying types are temporalily assigned for PoC.
pub type CipherText = Vec<u8>;
type PlainText = String;
type Number = u32;

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

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct Event {
    /// Secret shared and then encrypted match keys.
    pub matchkeys: Vec<SecretShare>,

    /// The epoch which this event is generated. Using an 8-bit value = 256 epochs > 4 years (assuming 1 epoch = 1 week).
    /// This field is in the clear.
    pub epoch: u8,

    /// An offset in seconds into a given epoch. The clear is u32 (< 2^20 seconds), then encrypted and secret shared.
    pub timestamp: SecretShare,
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct SourceEvent {
    pub event: Event,

    /// A key to group sets of the events.
    pub breakdown_key: Number,
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
pub struct TriggerEvent {
    pub event: Event,

    /// Conversion value.
    pub value: SecretShare,

    /// Zero knowledge proof that the trigger value lies within a specific range
    /// of values. The range is specified in [TriggerFanoutQuery].
    pub zkp: Number,
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
