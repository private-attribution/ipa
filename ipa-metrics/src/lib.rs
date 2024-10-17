mod collector;
mod context;
mod key;
mod kind;
mod label;
#[cfg(feature = "partitions")]
mod partitioned;
mod store;

pub use collector::{installer, MetricsCollector, MetricsCollectorController, MetricsProducer};
pub use context::{CurrentThreadContext as MetricsCurrentThreadContext, MetricsContext};
pub use key::{MetricName, OwnedName, UniqueElements};
pub use label::{Label, LabelValue};
#[cfg(feature = "partitions")]
pub use partitioned::{
    current_partition, set_or_unset_partition, set_partition, Partition as MetricPartition,
    PartitionedStore as MetricsStore,
};
#[cfg(not(feature = "partitions"))]
pub use store::Store as MetricsStore;

#[cfg(test)]
pub(crate) fn set_test_partition() {
    #[cfg(feature = "partitions")]
    partitioned::set_partition(0xdeadbeef)
}
