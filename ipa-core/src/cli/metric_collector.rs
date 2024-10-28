use std::{io::stderr, thread};

use metrics_tracing_context::TracingContextLayer;
use metrics_util::{
    debugging::{DebuggingRecorder, Snapshotter},
    layers::Layer,
};

use crate::telemetry::stats::Metrics;

/// Collects metrics using `DebuggingRecorder` and dumps them to `stderr` when dropped.
pub struct CollectorHandle {
    snapshotter: Snapshotter,
}

///
/// Initializes this collector by installing `DebuggingRecorder` to keep track of metrics
/// emitted from different parts of the app.
///
/// ## Panics
/// Panics if metric recorder has already been set
#[must_use]
pub fn install_collector() -> CollectorHandle {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    // use span fields as dimensions for metric
    let recorder = TracingContextLayer::all().layer(recorder);
    metrics::set_boxed_recorder(Box::new(recorder))
        .expect("Metric recorder has been installed already");

    // register metrics
    crate::telemetry::metrics::register();
    tracing::info!("Metrics enabled");

    CollectorHandle { snapshotter }
}

impl Drop for CollectorHandle {
    fn drop(&mut self) {
        if !thread::panicking() {
            let stats = Metrics::from_snapshot(self.snapshotter.snapshot());
            stats
                .print(&mut stderr())
                .expect("Failed to dump metrics to stderr");
        }
    }
}
