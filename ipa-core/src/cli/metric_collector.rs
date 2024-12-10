use std::{io, thread, thread::JoinHandle};

use ipa_metrics::{
    MetricChannelType, MetricsCollectorController, MetricsCurrentThreadContext, MetricsProducer,
};
use ipa_metrics_prometheus::PrometheusMetricsExporter;
use tokio::runtime::Builder;

/// Holds a reference to metrics controller and producer
pub struct CollectorHandle {
    thread_handle: JoinHandle<()>,
    /// This will be used once we start consuming metrics
    controller: MetricsCollectorController,
    producer: MetricsProducer,
}

///
/// Initializes this collector by installing `DebuggingRecorder` to keep track of metrics
/// emitted from different parts of the app.
///
/// ## Errors
/// If it fails to start a new thread
pub fn install_collector() -> io::Result<CollectorHandle> {
    let (producer, controller, handle) =
        ipa_metrics::install_new_thread(MetricChannelType::Unbounded)?;
    tracing::info!("Metrics engine is enabled");

    Ok(CollectorHandle {
        thread_handle: handle,
        controller,
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

    /// Export the metrics to be consumed by metrics scraper, e.g. Prometheus
    ///
    /// # Panics
    /// If metrics is not initialized
    #[must_use]
    pub fn scrape_metrics(&self) -> Vec<u8> {
        let mut store = self.controller.snapshot().expect("Metrics must be set up");
        let mut buff = Vec::new();
        store.export(&mut buff);

        buff
    }
}
