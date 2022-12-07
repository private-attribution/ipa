//! Metric-aware PRSS decorators

use crate::helpers::Role;
use crate::protocol::prss::{
    IndexedSharedRandomness, SequentialSharedRandomness, SharedRandomness,
};
use crate::protocol::Step;
use crate::telemetry::labels::{ROLE, STEP};
use crate::telemetry::metrics::{INDEXED_PRSS_GENERATED, SEQUENTIAL_PRSS_GENERATED};
use rand_core::{Error, RngCore};
use std::sync::Arc;

/// Wrapper around `IndexedSharedRandomness` that instrument calls to `generate_values`
pub struct InstrumentedIndexedSharedRandomness<'a> {
    inner: Arc<IndexedSharedRandomness>,
    step: &'a Step,
    role: Role,
}

impl<'a> InstrumentedIndexedSharedRandomness<'a> {
    pub fn new(source: Arc<IndexedSharedRandomness>, step: &'a Step, role: Role) -> Self {
        Self {
            inner: source,
            step,
            role,
        }
    }
}

impl SharedRandomness for InstrumentedIndexedSharedRandomness<'_> {
    fn generate_values<I: Into<u128>>(&self, index: I) -> (u128, u128) {
        let step = self.step.as_ref().to_string();
        metrics::increment_counter!(INDEXED_PRSS_GENERATED, STEP => step, ROLE => self.role.as_static_str());
        self.inner.generate_values(index)
    }
}

/// Wrapper for `SequentialSharedRandomness` that instrument calls to generate random values.
pub struct InstrumentedSequentialSharedRandomness<'a> {
    inner: SequentialSharedRandomness,
    step: &'a Step,
    role: Role,
}

impl<'a> InstrumentedSequentialSharedRandomness<'a> {
    pub fn new(source: SequentialSharedRandomness, step: &'a Step, role: Role) -> Self {
        Self {
            inner: source,
            step,
            role,
        }
    }
}

impl RngCore for InstrumentedSequentialSharedRandomness<'_> {
    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        let step = self.step.as_ref().to_string();
        metrics::increment_counter!(SEQUENTIAL_PRSS_GENERATED, STEP => step, ROLE => self.role.as_static_str());
        self.inner.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.inner.try_fill_bytes(dest)
    }
}
