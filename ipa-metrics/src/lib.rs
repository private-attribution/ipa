mod collector;
mod context;
mod key;
mod kind;
mod label;
mod store;
#[cfg(feature = "partitions")]
mod partitioned;

pub use key::MetricName;
pub use label::LabelValue;
#[cfg(not(feature = "partitions"))]
pub use store::Store as MetricsStore;

#[cfg(feature = "partitions")]
pub use partitioned::PartitionedStore as MetricsStore;

#[cfg(test)]
pub(crate) fn set_test_partition() {
    #[cfg(feature = "partitions")]
    partitioned::set_partition(0xdeadbeef)
}
