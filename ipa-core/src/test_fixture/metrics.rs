use ipa_metrics::{
    MetricsCollector, MetricsCollectorController, MetricsContext, MetricsCurrentThreadContext,
    MetricsProducer,
};
use metrics::KeyName;
use metrics_tracing_context::TracingContextLayer;
use metrics_util::{
    debugging::{DebuggingRecorder, Snapshotter},
    layers::Layer,
};
use once_cell::sync::OnceCell;
use rand::distributions::Alphanumeric;
use tracing::{Level, Span};

use crate::{
    rand::{thread_rng, Rng},
    telemetry::{metrics::register, stats::Metrics},
    test_fixture::logging,
};

// TODO: move to OnceCell from std once it is stabilized
static ONCE: OnceCell<(MetricsProducer, MetricsCollectorController)> = OnceCell::new();

fn setup() {
    // logging is required to import span fields as metric values
    logging::setup();

    ONCE.get_or_init(|| {
        assert!(
            metrics::try_recorder().is_none(),
            "metric recorder has already been installed"
        );
        let (collector, producer, controller) = ipa_metrics::installer();

        // we can't set up the current thread as metric collector. It is possible
        // that it will be shut down right after this call and we will lose metrics.
        std::thread::Builder::new()
            .name("ipa-metric-collector".to_string())
            .spawn(move || {
                // todo: expose the join handle to drop the thread
                collector.install();
                MetricsCollector::wait_for_shutdown();
            })
            .unwrap(); // no null bytes

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        // Leaking the recorder is necessary for metrics infrastructure to work.
        // it does not use `seq_join` or `parallel_join`.
        #[allow(clippy::disallowed_methods)]
        let recorder = Box::leak(Box::new(TracingContextLayer::all().layer(recorder)));

        #[cfg(not(feature = "disable-metrics"))]
        metrics::set_recorder(recorder).unwrap();

        // register metrics
        register();

        (producer, controller)
    });
}

#[derive(Clone)]
pub struct MetricsHandle {
    id: String,
    level: Level,
}

impl MetricsHandle {
    /// Creates a new metrics handle with a unique id. Id is used to partition metrics emitted while
    /// this handle is not dropped. Handle holds onto a tracing span and every metric emitted inside
    /// any children span will have a label associated with this handle's identifier.
    ///
    /// There must be additional support for components that use multithreading/async because they
    /// break span hierarchy. Most infrastructure components (Gateway, PRSS) support it, but others
    /// may not.
    #[must_use]
    pub fn new(level: Level) -> Self {
        MetricsHandle {
            id: thread_rng()
                .sample_iter(&Alphanumeric)
                .take(8)
                .map(char::from)
                .collect(),
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
        // connect current thread to the metrics collector, if not installed yet
        if !MetricsCurrentThreadContext::is_connected() {
            tracing::warn!("metrics started on {:?}", std::thread::current().id());
            producer.install();
        }

        // Metrics collection with attributes/labels is expensive. Enabling it for all tests
        // resulted in doubling the time it takes to finish them. Tests must explicitly opt-in to
        // use this feature.
        // Tests that verify metric values must set the span verbosity level to Info.
        // Tests that don't care will set the verbosity level to Debug. In case if metrics need
        // to be seen by a human `RUST_LOG=ipa::debug` environment variable must be set to
        // print them.
        match self.level {
            Level::INFO => {
                tracing::info_span!(
                    "",
                    "metrics_id" = self.id,
                    "metrics-partition" = to_u128(&self.id)
                )
            }
            Level::DEBUG => {
                tracing::debug_span!(
                    "",
                    "metrics_id" = self.id,
                    "metrics-partition" = to_u128(&self.id)
                )
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

        // TODO: this is plain wrong, we need to get the snapshot from the collector thread.
        // because we may use parallel seq_join
        // let snapshot = MetricsContext::current_thread(|ctx| {
        let metrics = Metrics::from_partition(&store, to_u128(&self.id));
        metrics

        // let snapshot = ONCE.get().unwrap().snapshot();
        //
        // Metrics::with_filter(snapshot, |labels| {
        //     labels.iter().any(|label| label.value().eq(&self.id))
        // })
    }

    pub fn get_counter_value<K: Into<KeyName>>(&self, key_name: K) -> Option<u64> {
        let snapshot = self.snapshot();
        snapshot
            .counters
            .get(&key_name.into())
            .map(|v| v.total_value)
    }
}

fn to_u128(input: &str) -> u128 {
    let mut c = [0_u8; 16];
    c[0..8].copy_from_slice(input.as_bytes());

    u128::from_le_bytes(c)
}

#[cfg(feature = "web-app")]
impl crate::net::TracingSpanMaker for MetricsHandle {
    fn make_span(&self) -> Span {
        self.span()
    }
}
