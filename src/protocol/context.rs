use crate::helpers::prss::{Participant, SpaceIndex};

use super::{securemul::SecureMul, RecordId, Step};

/// Context used by each helper to perform computation. Currently they need access to shared
/// randomness generator (see `Participant`) and communication trait to send messages to each other.

#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct ProtocolContext<'a, G, S: SpaceIndex> {
    participant: &'a Participant<S>,
    pub gateway: &'a G,
}

impl<'a, G, S: Step + SpaceIndex> ProtocolContext<'a, G, S> {
    pub fn new(participant: &'a Participant<S>, gateway: &'a G) -> Self {
        Self {
            participant,
            gateway,
        }
    }

    /// Request multiplication for a given record. This function is intentionally made async
    /// to allow backpressure if infrastructure layer cannot keep up with protocols demand.
    /// In this case, function returns only when multiplication for this record can actually
    /// be processed.
    pub async fn multiply(&'a self, record_id: RecordId, step: S) -> SecureMul<'a, G, S> {
        SecureMul::new(&self.participant[step], self.gateway, step, record_id)
    }
}
