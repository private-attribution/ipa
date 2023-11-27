//! Metric-aware PRSS decorators

use rand_core::{Error, RngCore};

use crate::{
    helpers::Role,
    protocol::{
        prss::{IndexedSharedRandomness, SequentialSharedRandomness, SharedRandomness},
        step::Gate,
    },
    sync::Arc,
    telemetry::{
        labels::{ROLE, STEP},
        metrics::{INDEXED_PRSS_GENERATED, SEQUENTIAL_PRSS_GENERATED},
    },
};

/// Wrapper around `IndexedSharedRandomness` that instrument calls to `generate_values`
pub struct InstrumentedIndexedSharedRandomness<'a> {
    inner: Arc<IndexedSharedRandomness>,
    step: &'a Gate,
    role: Role,
}

impl<'a> InstrumentedIndexedSharedRandomness<'a> {
    #[must_use]
    pub fn new(source: Arc<IndexedSharedRandomness>, step: &'a Gate, role: Role) -> Self {
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
        // TODO: what we really want here is a gauge indicating the maximum index used to generate
        // PRSS. Gauge infrastructure is not supported yet, `Metrics` struct needs to be able to
        // handle gauges
        metrics::increment_counter!(INDEXED_PRSS_GENERATED, STEP => step, ROLE => self.role.as_static_str());
        self.inner.generate_values(index)
    }
}

/// Wrapper for `SequentialSharedRandomness` that instrument calls to generate random values.
pub struct InstrumentedSequentialSharedRandomness<'a> {
    inner: SequentialSharedRandomness,
    step: &'a Gate,
    role: Role,
}

impl<'a> InstrumentedSequentialSharedRandomness<'a> {
    #[must_use]
    pub fn new(source: SequentialSharedRandomness, step: &'a Gate, role: Role) -> Self {
        Self {
            inner: source,
            step,
            role,
        }
    }
}

impl RngCore for InstrumentedSequentialSharedRandomness<'_> {
    #[allow(clippy::cast_possible_truncation)]
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        let step = self.step.as_ref().to_string();
        metrics::increment_counter!(SEQUENTIAL_PRSS_GENERATED, STEP => step, ROLE => self.role.as_static_str());
        self.inner.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.inner.try_fill_bytes(dest)
    }
}
