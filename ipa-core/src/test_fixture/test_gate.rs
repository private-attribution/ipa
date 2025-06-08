use std::sync::atomic::{AtomicUsize, Ordering};

use ipa_step::StepNarrow;

use crate::protocol::{Gate, step::TestExecutionStep};

/// This manages the gate information for test runs. Most unit tests want to have multiple runs
/// using the same instance of [`TestWorld`], but they don't care about the name of that particular
/// gate.
///
/// A few tests and some benchmarks want to execute the actual protocol, but they also care about
/// performance they use compact gate to manage step transitions.
/// Compact gate has strict narrowing requirements, so these tests want to set the initial gate
/// to the root of the particular protocol.
///
/// There are two implementations for common use cases: tests that don't care about having specific
/// gates set, will use [`Unique`] which is the default behavior and benchmarks will use [`Fixed`]
///
/// [`TestWorld`]: super::TestWorld
pub(super) trait TestGateVendor: Send + Sync + 'static {
    fn current(&self) -> Gate;
    fn next(&self) -> Gate;
}

/// If input is set, returns a vendor that yields it, otherwise returns an instance that returns
/// a unique gate per test run.
///
pub(super) fn gate_vendor(input: Option<Gate>) -> Box<dyn TestGateVendor> {
    if let Some(initial_gate) = input {
        Box::new(Fixed(initial_gate))
    } else {
        Box::<Unique>::default()
    }
}

/// This provides a unique gate name per test run.
#[derive(Default)]
pub(super) struct Unique(AtomicUsize);

/// This sets a fixed gate name for all test runs, which implies there can be at most one run
/// per [`TestWorld`].
pub(super) struct Fixed(Gate);

impl TestGateVendor for Fixed {
    fn current(&self) -> Gate {
        self.0.clone()
    }

    fn next(&self) -> Gate {
        self.0.clone()
    }
}

impl TestGateVendor for Unique {
    fn current(&self) -> Gate {
        let cur = self.0.load(Ordering::Relaxed);
        Gate::default().narrow(&TestExecutionStep::Iter(cur))
    }

    fn next(&self) -> Gate {
        let next_step = self.0.fetch_add(1, Ordering::AcqRel);
        Gate::default().narrow(&TestExecutionStep::Iter(next_step))
    }
}
