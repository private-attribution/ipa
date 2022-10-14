use crate::helpers::fabric::Network;
use crate::helpers::messaging::Gateway;
use crate::helpers::prss::{Participant, SpaceIndex};
use crate::helpers::Identity;

use super::{securemul::SecureMul, sort::reveal::Reveal, RecordId, Step};

/// Context used by each helper to perform computation. Currently they need access to shared
/// randomness generator (see `Participant`) and communication trait to send messages to each other.

#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct ProtocolContext<'a, S: SpaceIndex, F> {
    pub participant: &'a Participant<S>,
    pub gateway: &'a Gateway<S, F>,
    pub identity: Identity,
}

impl<'a, S: Step + SpaceIndex, F: Network<S>> ProtocolContext<'a, S, F> {
    pub fn new(
        participant: &'a Participant<S>,
        gateway: &'a Gateway<S, F>,
        identity: Identity,
    ) -> Self {
        Self {
            participant,
            gateway,
            identity,
        }
    }

    /// Request multiplication for a given record. This function is intentionally made async
    /// to allow backpressure if infrastructure layer cannot keep up with protocols demand.
    /// In this case, function returns only when multiplication for this record can actually
    /// be processed.
    #[allow(clippy::unused_async)] // eventually there will be await b/c of backpressure implementation
    pub async fn multiply(&'a self, record_id: RecordId, step: S) -> SecureMul<'a, S, F> {
        SecureMul::new(&self.participant[step], self.gateway, step, record_id)
    }

    /// Request reveal for a given record.
    #[allow(clippy::unused_async)] // eventually there will be await b/c of backpressure implementation
    pub fn reveal(&'a self, record_id: RecordId, step: S) -> Reveal<'a, F, S> {
        Reveal::new(self.gateway, step, record_id)
    }
}
