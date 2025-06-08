#![deny(clippy::pedantic)]
#![allow(clippy::similar_names)]
#![allow(clippy::module_name_repetitions)]

mod layer;

pub use layer::{FIELD as PARTITION_FIELD, MetricsPartitioningLayer};
