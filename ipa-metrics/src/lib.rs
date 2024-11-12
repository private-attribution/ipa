#![deny(clippy::pedantic)]
#![allow(clippy::similar_names)]
#![allow(clippy::module_name_repetitions)]

mod collector;
mod context;
mod controller;
mod exporter;
mod key;
mod kind;
mod label;
#[cfg(feature = "partitions")]
mod partitioned;
mod producer;
mod store;

use std::{io, thread::JoinHandle};

pub use collector::MetricsCollector;
pub use context::{CurrentThreadContext as MetricsCurrentThreadContext, MetricsContext};
pub use controller::{
    Command as ControllerCommand, Controller as MetricsCollectorController,
    Status as ControllerStatus,
};
pub use key::{MetricName, OwnedName, UniqueElements};
pub use label::{label_hasher, Label, LabelValue};
#[cfg(feature = "partitions")]
pub use partitioned::{
    CurrentThreadContext as CurrentThreadPartitionContext, Partition as MetricPartition,
    PartitionedStore as MetricsStore,
};
pub use producer::Producer as MetricsProducer;
#[cfg(not(feature = "partitions"))]
pub use store::Store as MetricsStore;

/// Type of the communication channel between metric producers
/// and the collector.
#[derive(Copy, Clone)]
pub enum MetricChannelType {
    /// Each send message must be paired with receive. Sends that
    /// don't get a pair block the thread until collector processes
    /// the request. This mode is suitable for unit tests where metric
    /// consistency is important and gets more priority than availability.
    Rendezvous,
    /// Each channel between producer and collector gets unlimited capacity.
    Unbounded,
}

/// Creates metric infrastructure that is ready to use
/// in the application code. It consists a triple of
/// [`MetricsCollector`], [`MetricsProducer`], and
/// [`MetricsCollectorController`].
///
/// Collector is used in the centralized place (a dedicated thread)
/// to collect metrics coming from thread local stores.
///
/// Metric producer must be installed on every thread that is used
/// to emit telemetry, and it connects that thread to the collector.
///
/// Controller provides command-line API interface to the collector.
/// A thread that owns the controller, can request current snapshot.
/// For more information about API, see [`Command`].
///
/// The communication channel between producers and collector is configured
/// via `channel_type` parameter. See [`MetricChannelType`] for details
///
/// ## Example 1 (Rendezvous channels)
/// ```rust
/// use ipa_metrics::MetricChannelType;
/// let (collector, producer, controller) = ipa_metrics::install(MetricChannelType::Rendezvous);
/// ```
///
/// ## Example 2 (unbounded)
/// ```rust
/// use ipa_metrics::MetricChannelType;
/// let (collector, producer, controller) = ipa_metrics::install(MetricChannelType::Unbounded);
/// ```
///
/// [`MetricsCollector`]: crate::MetricsCollector
/// [`MetricsProducer`]: crate::MetricsProducer
/// [`MetricsCollectorController`]: crate::MetricsCollectorController
/// [`Command`]: crate::ControllerCommand
#[must_use]
pub fn install(
    channel_type: MetricChannelType,
) -> (
    MetricsCollector,
    MetricsProducer,
    MetricsCollectorController,
) {
    let (command_tx, command_rx) = crossbeam_channel::unbounded();
    let (tx, rx) = match channel_type {
        MetricChannelType::Rendezvous => crossbeam_channel::bounded(0),
        MetricChannelType::Unbounded => crossbeam_channel::unbounded(),
    };
    (
        MetricsCollector {
            rx,
            local_store: MetricsStore::default(),
            command_rx,
        },
        MetricsProducer { tx },
        MetricsCollectorController { tx: command_tx },
    )
}

/// Same as [`install`] but spawns a new thread to run the collector.
///
/// ## Errors
/// if thread cannot be started
pub fn install_new_thread(
    channel_type: MetricChannelType,
) -> io::Result<(MetricsProducer, MetricsCollectorController, JoinHandle<()>)> {
    let (collector, producer, controller) = install(channel_type);
    let handle = std::thread::Builder::new()
        .name("metric-collector".to_string())
        .spawn(|| {
            collector.install().block_until_shutdown();
        })?;

    Ok((producer, controller, handle))
}
