mod collector;
mod context;
mod controller;
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
pub use controller::{Command as ControllerCommand, Controller as MetricsCollectorController};
pub use key::{MetricName, OwnedName, UniqueElements};
pub use label::{Label, LabelValue};
#[cfg(feature = "partitions")]
pub use partitioned::{
    CurrentThreadContext as CurrentThreadPartitionContext, Partition as MetricPartition,
    PartitionedStore as MetricsStore,
};
pub use producer::Producer as MetricsProducer;
#[cfg(not(feature = "partitions"))]
pub use store::Store as MetricsStore;

pub fn installer() -> (
    MetricsCollector,
    MetricsProducer,
    MetricsCollectorController,
) {
    let (command_tx, command_rx) = crossbeam_channel::unbounded();
    let (tx, rx) = crossbeam_channel::unbounded();
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

pub fn thread_installer(
) -> io::Result<(MetricsProducer, MetricsCollectorController, JoinHandle<()>)> {
    let (collector, producer, controller) = installer();
    let handle = std::thread::Builder::new()
        .name("metric-collector".to_string())
        .spawn(|| {
            collector.install().block_until_shutdown();
        })?;

    Ok((producer, controller, handle))
}
