use crate::cli::Metrics;
use crate::test_fixture::logging;
use metrics::KeyName;
use metrics_tracing_context::TracingContextLayer;
use metrics_util::debugging::{DebuggingRecorder, Snapshotter};
use metrics_util::layers::Layer;
use once_cell::sync::OnceCell;
use rand::{thread_rng, Rng};
use tracing::span::EnteredSpan;
use tracing::Level;

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

        snapshotter
    });
}

pub struct MetricsHandle {
    id: u128,
    _span: EnteredSpan,
}

impl MetricsHandle {
    /// Creates a new handle
    ///
    /// ## Panics
    /// If the provided level is not set to either debug or info
    #[must_use]
    pub fn new(level: Level) -> Self {
        setup();

        // logging is required to import span fields as metric values
        logging::setup();

        let id = thread_rng().gen::<u128>();

        // Metrics collection with attributes/labels is expensive. Enabling it for all tests
        // resulted in 100% penalty, so tests must explicitly opt-in to it.
        // Some tests that check metric values would want to set the span level to Info.
        // others, where metrics are optional, will use `RUST_LOG=raw_ipa::debug` environment variable
        let span = match level {
            Level::INFO => {
                tracing::info_span!("", "metric_handle_id" = id.to_string())
            }
            Level::DEBUG => {
                tracing::debug_span!("", "metric_handle_id" = id.to_string())
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
        let id = self.id.to_string();

        Metrics::with_filter(snapshot, |labels| {
            labels.iter().any(|label| label.value().eq(&id))
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
