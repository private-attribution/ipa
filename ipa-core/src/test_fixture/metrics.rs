use std::sync::OnceLock;

use ipa_metrics::{
    MetricChannelType, MetricPartition, MetricsCollectorController, MetricsCurrentThreadContext,
    MetricsProducer,
};
use rand::random;
use tracing::{Level, Span};

use crate::{telemetry::stats::Metrics, test_fixture::logging};

static ONCE: OnceLock<(MetricsProducer, MetricsCollectorController)> = OnceLock::new();

fn setup() {
    // logging is required to import span fields as metric values
    logging::setup();

    ONCE.get_or_init(|| {
        let (producer, controller, _handle) =
            ipa_metrics::install_new_thread(MetricChannelType::Rendezvous).unwrap();

        (producer, controller)
    });
}

#[derive(Clone)]
pub struct MetricsHandle {
    id: MetricPartition,
    level: Level,
}

impl MetricsHandle {
    /// Creates a new metrics handle with a unique id. Id is used to partition metrics emitted while
    /// this handle is not dropped. Handle holds onto a tracing span and every metric emitted inside
    /// any children span will have a label associated with this handle's identifier.
    #[must_use]
    pub fn new(level: Level) -> Self {
        MetricsHandle {
            id: random(),
            level,
        }
    }

    /// Get a span for tracing at the indicated level.
    ///
    /// ## Panics
    /// If the provided level is not set to either debug or info.
    #[must_use]
    pub fn span(&self) -> Span {
        setup();

        // safety: we call setup that initializes metrics right above this.
        let (producer, _) = ONCE.get().unwrap();

        // connect current thread to the metrics collector, if not connected yet
        if !MetricsCurrentThreadContext::is_connected() {
            producer.install();
        }

        match self.level {
            Level::INFO => {
                tracing::info_span!("", { ipa_metrics_tracing::PARTITION_FIELD } = self.id,)
            }
            Level::DEBUG => {
                tracing::debug_span!("", { ipa_metrics_tracing::PARTITION_FIELD } = self.id,)
            }
            _ => {
                panic!("Only Info and Debug levels are supported")
            }
        }
    }

    /// Returns the current snapshot. Only metrics associated with this handle will be included
    ///
    /// ## Panics
    /// if metrics recorder is not installed
    #[must_use]
    pub fn snapshot(&self) -> Metrics {
        let (_, controller) = ONCE.get().expect("metrics must be installed");
        let store = controller
            .snapshot()
            .expect("metrics snapshot must be available");

        Metrics::from_partition(&store, self.id)
    }

    pub fn get_counter_value<K: Into<&'static str>>(&self, key_name: K) -> Option<u64> {
        let snapshot = self.snapshot();
        snapshot
            .counters
            .get(&key_name.into())
            .map(|v| v.total_value)
    }
}

#[cfg(feature = "web-app")]
impl crate::net::TracingSpanMaker for MetricsHandle {
    fn make_span(&self) -> Span {
        self.span()
    }
}
