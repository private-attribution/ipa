use crate::{
    telemetry::{metrics::register, stats::Metrics},
    test_fixture::logging,
};
use metrics::KeyName;
use metrics_tracing_context::TracingContextLayer;
use metrics_util::{
    debugging::{DebuggingRecorder, Snapshotter},
    layers::Layer,
};
use once_cell::sync::OnceCell;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use tracing::{span::EnteredSpan, Level};

// TODO: move to OnceCell from std once it is stabilized
static ONCE: OnceCell<Snapshotter> = OnceCell::new();

fn setup() {
    ONCE.get_or_init(|| {
        assert!(
            metrics::try_recorder().is_none(),
            "metric recorder has already been installed"
        );

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let recorder = Box::leak(Box::new(TracingContextLayer::all().layer(recorder)));
        metrics::set_recorder(recorder).unwrap();

        // register metrics
        register();

        snapshotter
    });
}

pub struct MetricsHandle {
    id: String,
    _span: EnteredSpan,
}

impl MetricsHandle {
    /// Creates a new metrics handle with a unique id. Id is used to partition metrics emitted while
    /// this handle is not dropped. Handle holds onto a tracing span and every metric emitted inside
    /// any children span will have a label associated with this handle's identifier.
    ///
    /// There must be additional support for components that use multithreading/async because they
    /// break span hierarchy. Most infrastructure components (Gateway, PRSS) support it, but others
    /// may not.
    ///
    /// ## Panics
    /// If the provided level is not set to either debug or info
    #[must_use]
    pub fn new(level: Level) -> Self {
        setup();

        // logging is required to import span fields as metric values
        logging::setup();

        let id = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect();

        // Metrics collection with attributes/labels is expensive. Enabling it for all tests
        // resulted in doubling the time it takes to finish them. Tests must explicitly opt-in to
        // use this feature.
        // Tests that verify metric values must set the span verbosity level to Info.
        // Tests that don't care will set the verbosity level to Debug. In case if metrics need
        // to be seen by a human `RUST_LOG=ipa::debug` environment variable must be set to
        // print them
        let span = match level {
            Level::INFO => {
                tracing::info_span!("", "metrics_id" = id)
            }
            Level::DEBUG => {
                tracing::debug_span!("", "metrics_id" = id)
            }
            _ => {
                panic!("Only Info and Debug levels are supported")
            }
        };

        MetricsHandle {
            id,
            _span: span.entered(),
        }
    }

    /// Returns the current snapshot. Only metrics associated with this handle will be included
    ///
    /// ## Panics
    /// if metrics recorder is not installed
    #[must_use]
    pub fn snapshot(&self) -> Metrics {
        let snapshot = ONCE.get().unwrap().snapshot();

        Metrics::with_filter(snapshot, |labels| {
            labels.iter().any(|label| label.value().eq(&self.id))
        })
    }

    pub fn get_counter_value<K: Into<KeyName>>(&self, key_name: K) -> Option<u64> {
        let snapshot = self.snapshot();
        snapshot
            .counters
            .get(&key_name.into())
            .map(|v| v.total_value)
    }
}
