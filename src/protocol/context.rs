use std::sync::Arc;

use super::{
    prss::{IndexedSharedRandomness, SequentialSharedRandomness},
    securemul::SecureMul,
    RecordId, Step, UniqueStepId,
};
use crate::{
    field::Field,
    helpers::{
        fabric::Network,
        messaging::{Gateway, Mesh},
        Identity,
    },
    protocol::{malicious::SecurityValidatorAccumulator, prss::Endpoint as PrssEndpoint},
};

/// Context used by each helper to perform computation. Currently they need access to shared
/// randomness generator (see `Participant`) and communication trait to send messages to each other.
#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug)]
pub struct ProtocolContext<'a, N, F> {
    role: Identity,
    step: UniqueStepId,
    prss: &'a PrssEndpoint,
    gateway: &'a Gateway<N>,
    accumulator: Option<SecurityValidatorAccumulator<F>>,
}

impl<'a, N, F> ProtocolContext<'a, N, F> {
    pub fn new(role: Identity, participant: &'a PrssEndpoint, gateway: &'a Gateway<N>) -> Self {
        Self {
            role,
            step: UniqueStepId::default(),
            prss: participant,
            gateway,
            accumulator: None,
        }
    }

    pub fn upgrade_to_malicious(self, accumulator: SecurityValidatorAccumulator<F>) -> Self {
        ProtocolContext {
            role: self.role,
            step: self.step,
            prss: self.prss,
            gateway: self.gateway,
            accumulator: Some(accumulator),
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
    pub fn narrow<S: Step + ?Sized>(&self, step: &S) -> Self {
        ProtocolContext {
            role: self.role,
            step: self.step.narrow(step),
            prss: self.prss,
            gateway: self.gateway,
            // TODO: make this work
            // accumulator: self.accumulator, //TODO: make this work
            accumulator: None, // God help me, I just can't make this work
        }
    }

    /// Get the indexed PRSS instance for this step.  It is safe to call this function
    /// multiple times.
    ///
    /// # Panics
    /// If `prss_rng()` is invoked for the same context, this will panic.  Use of
    /// these two functions are mutually exclusive.
    #[must_use]
    pub fn prss(&self) -> Arc<IndexedSharedRandomness> {
        self.prss.indexed(&self.step)
    }

    /// Get a pair of PRSS-based RNGs.  The first is shared with the helper to the "left",
    /// the second is shared with the helper to the "right".
    ///
    /// # Panics
    /// This method can only be called once.  This is also mutually exclusive with `prss()`.
    /// This will panic if you have previously invoked `prss()`.
    #[must_use]
    pub fn prss_rng(&self) -> (SequentialSharedRandomness, SequentialSharedRandomness) {
        self.prss.sequential(&self.step)
    }
}

impl<'a, N: Network, F: Field> ProtocolContext<'a, N, F> {
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
    pub async fn multiply(self, record_id: RecordId) -> SecureMul<'a, N, F> {
        SecureMul::new(self, record_id)
    }

    /// ## Panics
    /// If you failed to upgrade to malicious protocol context
    pub async fn malicious_multiply(self, _record_id: RecordId) {
        // -> MaliciouslySecureMul<'a, N, F> {
        let _accumulator = self.accumulator.as_ref().unwrap().clone();
        // TODO: next diff!
        // MaliciouslySecureMul::new(self, record_id, accumulator)
    }
}
