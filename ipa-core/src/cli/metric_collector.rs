use std::{io, thread, thread::JoinHandle};
use std::collections::HashMap;
use std::time::Duration;
use ipa_metrics::{counter, MetricChannelType, MetricsCollectorController, MetricsCurrentThreadContext, MetricsProducer};
use tokio::runtime::Builder;
use crate::protocol::context::BATCH_VALIDATE;

/// Holds a reference to metrics controller and producer
pub struct CollectorHandle {
    thread_handle: JoinHandle<()>,
    /// This will be used once we start consuming metrics
    // _controller: MetricsCollectorController,
    producer: MetricsProducer,
}

///
/// Initializes this collector by installing `DebuggingRecorder` to keep track of metrics
/// emitted from different parts of the app.
///
/// ## Errors
/// If it fails to start a new thread
pub fn install_collector() -> io::Result<CollectorHandle> {
    struct Watcher(MetricsCollectorController, HashMap<&'static str, u64>);
    impl Watcher {
        fn dump(&mut self) {
            if let Ok(snapshot) = self.0.snapshot() {
                let mut dump = String::new();
                let mut needs_dump = false;

                let metrics_of_interest = vec![
                    // DENOM_COMPUTES,
                    // DENOM_COMPUTES_8,
                    // DENOM_COMPUTES_15,
                    // DENOM_COMPUTES_32,
                    // DENOM_COMPUTES_63,
                    // DENOM_INVERTS,
                    BATCH_VALIDATE,
                ];

                for metric in metrics_of_interest {
                    let value = snapshot.counter_val(counter!(metric));
                    if value > 0 && self.1.get(metric) != Some(&value) {
                        self.1.insert(metric, value);
                        needs_dump = true;
                    }
                    if needs_dump {
                        dump += &format!("{metric}={value}\n");
                    }
                }

                if !dump.is_empty() {
                    tracing::info!("Metrics dump:\n{dump}");
                }
            } else {
                tracing::error!("Failed to dump metrics");
            }
        }
    }

    impl Drop for Watcher {
        fn drop(&mut self) {
            tracing::info!("metric watcher is being dropped");
            self.dump();
        }
    }
    let (producer, controller, handle) =
        ipa_metrics::install_new_thread(MetricChannelType::Unbounded)?;
    tracing::info!("Metrics engine is enabled");
    thread::spawn(|| {
        tracing::info!("metric observer is started");
        let mut w = Watcher(controller, HashMap::default());
        loop {
            thread::sleep(Duration::from_secs(10));
            w.dump();
        }
    });

    Ok(CollectorHandle {
        thread_handle: handle,
        // _controller: controller,
        producer,
    })
}

impl Drop for CollectorHandle {
    fn drop(&mut self) {
        if !thread::panicking() && !self.thread_handle.is_finished() {
            tracing::warn!("Metrics thread is still running");
        };
    }
}

impl CollectorHandle {
    pub fn tokio_bind<'a>(&self, target: &'a mut Builder) -> &'a mut Builder {
        let flush_fn = || MetricsCurrentThreadContext::flush();

        target
            .on_thread_start({
                let producer = self.producer.clone();
                move || {
                    producer.install();
                }
            })
            .on_thread_stop(flush_fn)
            .on_thread_park(flush_fn)
    }
}
