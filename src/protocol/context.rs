use super::{prss::PrssSpace, securemul::SecureMul, RecordId, Step, UniqueStepId};
use crate::{
    helpers::{
        fabric::Network,
        messaging::{Gateway, Mesh},
        Identity,
    },
    protocol::{prss::Participant, reveal::Reveal},
};
use std::sync::Arc;

/// Context used by each helper to perform computation. Currently they need access to shared
/// randomness generator (see `Participant`) and communication trait to send messages to each other.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct ProtocolContext<'a, N> {
    role: Identity,
    step: UniqueStepId,
    participant: &'a Participant,
    gateway: &'a Gateway<N>,
}

impl<'a, N> ProtocolContext<'a, N> {
    pub fn new(role: Identity, participant: &'a Participant, gateway: &'a Gateway<N>) -> Self {
        Self {
            role,
            step: UniqueStepId::default(),
            participant,
            gateway,
        }
    }

    /// The role of this context.
    #[must_use]
    pub fn role(&self) -> Identity {
        self.role
    }

    /// A unique identifier for this stage of the protocol execution.
    #[must_use]
    pub fn step(&self) -> &UniqueStepId {
        &self.step
    }

    /// Make a sub-context.
    /// Note that each invocation of this should use a unique value of `step`.
    #[must_use]
    pub fn narrow<S: Step>(&self, step: &S) -> Self {
        ProtocolContext {
            role: self.role,
            step: self.step.narrow(step),
            participant: self.participant,
            gateway: self.gateway,
        }
    }

    /// Get the PRSS instance for this step.
    #[must_use]
    pub fn prss(&self) -> Arc<PrssSpace> {
        self.participant.prss(&self.step)
    }
}

impl<N: Network> ProtocolContext<'_, N> {
    /// Get a set of communications channels to different peers.
    #[must_use]
    pub fn mesh(&self) -> Mesh<'_, '_, N> {
        self.gateway.mesh(&self.step)
    }

    /// Request multiplication for a given record. This function is intentionally made async
    /// to allow backpressure if infrastructure layer cannot keep up with protocols demand.
    /// In this case, function returns only when multiplication for this record can actually
    /// be processed.
    #[allow(clippy::unused_async)] // eventually there will be await b/c of backpressure implementation
    pub async fn multiply(&self, record_id: RecordId) -> SecureMul<'_, N> {
        SecureMul::new(self.prss(), self.gateway, &self.step, record_id)
    }

    /// Request reveal for a given record.
    #[allow(clippy::unused_async)] // eventually there will be await b/c of backpressure implementation
    #[must_use]
    pub fn reveal(&self, record_id: RecordId) -> Reveal<'_, '_, N> {
        Reveal::new(self, record_id)
    }
}
