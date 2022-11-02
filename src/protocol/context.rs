use std::sync::Arc;

use super::{
    maliciously_secure_mul::MaliciouslySecureMul,
    prss::{IndexedSharedRandomness, SequentialSharedRandomness},
    securemul::SecureMul,
    RecordId, Step, UniqueStepId,
};
use crate::{
    ff::Field,
    helpers::{
        messaging::{Gateway, Mesh},
        Identity,
    },
    protocol::{malicious::SecurityValidatorAccumulator, prss::Endpoint as PrssEndpoint},
};

/// Context used by each helper to perform computation. Currently they need access to shared
/// randomness generator (see `Participant`) and communication trait to send messages to each other.
#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug)]
pub struct ProtocolContext<'a, F> {
    role: Identity,
    step: UniqueStepId,
    prss: &'a PrssEndpoint,
    gateway: &'a Gateway,
    accumulator: Option<SecurityValidatorAccumulator<F>>,
}

impl<'a, F: Field> ProtocolContext<'a, F> {
    pub fn new(role: Identity, participant: &'a PrssEndpoint, gateway: &'a Gateway) -> Self {
        Self {
            role,
            step: UniqueStepId::default(),
            prss: participant,
            gateway,
            accumulator: None,
        }
    }

    #[must_use]
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
            accumulator: self.accumulator.clone(),
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

    /// Get a set of communications channels to different peers.
    #[must_use]
    pub fn mesh(&self) -> Mesh<'_, '_> {
        self.gateway.mesh(&self.step)
    }

    /// Request a multiplication for a given record.
    #[must_use]
    pub fn multiply(self, record_id: RecordId) -> SecureMul<'a, F> {
        SecureMul::new(self, record_id)
    }

    /// ## Panics
    /// If you failed to upgrade to malicious protocol context
    #[must_use]
    pub fn malicious_multiply(self, record_id: RecordId) -> MaliciouslySecureMul<'a, F> {
        let accumulator = self.accumulator.as_ref().unwrap().clone();
        MaliciouslySecureMul::new(self, record_id, accumulator)
    }
}
