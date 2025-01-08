//! This module enables metric partitioning that can be useful
//! when threads that emit metrics are shared across multiple executions.
//! A typical example for it are unit tests in Rust that share threads.
//! Having a global per-thread store would mean that it is not possible
//! to distinguish between different runs.
//!
//! Partitioning attempts to solve this with a global 16 byte identifier that
//! is set in thread local storage and read automatically by [`PartitionedStore`]
//!
//! Note that this module does not provide means to automatically set and unset
//! partitions. `ipa-metrics-tracing` defines a way to do it via tracing context
//! that is good enough for the vast majority of use cases.
//!
//! Because partitioned stores carry additional cost of extra lookup (partition -> store),
//! it is disabled by default and requires explicit opt-in via `partitioning` feature.

use std::{borrow::Borrow, cell::Cell};

use hashbrown::hash_map::Entry;
use rustc_hash::FxBuildHasher;

use crate::{
    key::OwnedMetricName,
    kind::CounterValue,
    store::{CounterHandle, Store},
    MetricName,
};

thread_local! {
    static PARTITION: Cell<Option<Partition>> = const { Cell::new(None) }
}

/// Each partition is a unique 8 byte value, meaning roughly 1B partitions
/// can be supported and the limiting factor is birthday bound.
pub type Partition = u64;

pub struct CurrentThreadContext;

impl CurrentThreadContext {
    pub fn set(new: Partition) {
        Self::toggle(Some(new));
    }

    pub fn toggle(new: Option<Partition>) {
        PARTITION.set(new);
    }

    #[must_use]
    pub fn get() -> Option<Partition> {
        PARTITION.get()
    }
}

/// Provides the same functionality as [`Store`], but partitioned
/// across many dimensions. There is an extra price for it, so
/// don't use it, unless you need it.
/// The dimension is set through [`std::thread::LocalKey`], so
/// each thread can set only one dimension at a time.
///
/// The API of this struct will match [`Store`] as they
/// can be used interchangeably.
#[derive(Clone, Debug)]
pub struct PartitionedStore {
    /// Set of stores partitioned by [`Partition`]
    inner: hashbrown::HashMap<Partition, Store, FxBuildHasher>,
    /// We don't want to lose metrics that are emitted when partitions are not set.
    /// So we provide a default store for those
    default_store: Store,
}

impl Default for PartitionedStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PartitionedStore {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: hashbrown::HashMap::with_hasher(FxBuildHasher),
            default_store: Store::new(),
        }
    }

    pub fn with_partition<F: FnOnce(&Store) -> T, T>(
        &self,
        partition: Partition,
        f: F,
    ) -> Option<T> {
        let store = self.inner.get(&partition);
        store.map(f)
    }

    pub fn merge(&mut self, other: Self) {
        for (partition, store) in other.inner {
            self.get_mut(Some(partition)).merge(store);
        }
        self.default_store.merge(other.default_store);
    }

    pub fn counter_val<'a, const LABELS: usize, B: Borrow<MetricName<'a, LABELS>>>(
        &'a self,
        key: B,
    ) -> CounterValue {
        let name = key.borrow();
        if let Some(partition) = CurrentThreadContext::get() {
            self.inner
                .get(&partition)
                .map(|store| store.counter_val(name))
                .unwrap_or_default()
        } else {
            self.default_store.counter_val(name)
        }
    }

    pub fn counter<'a, const LABELS: usize, B: Borrow<MetricName<'a, LABELS>>>(
        &'a mut self,
        key: B,
    ) -> CounterHandle<'a, LABELS> {
        self.get_mut(CurrentThreadContext::get()).counter(key)
    }

    pub fn counters(&self) -> impl Iterator<Item = (&OwnedMetricName, CounterValue)> {
        if let Some(partition) = CurrentThreadContext::get() {
            return match self.inner.get(&partition) {
                Some(store) => store.counters(),
                None => self.default_store.counters(),
            };
        }
        self.default_store.counters()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len() + self.default_store.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[allow(dead_code)]
    fn with_partition_mut<F: FnOnce(&mut Store) -> T, T>(
        &mut self,
        partition: Partition,
        f: F,
    ) -> T {
        let store = self.get_mut(Some(partition));
        f(store)
    }

    fn get_mut(&mut self, partition: Option<Partition>) -> &mut Store {
        if let Some(v) = partition {
            match self.inner.entry(v) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => entry.insert(Store::default()),
            }
        } else {
            &mut self.default_store
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        counter, metric_name,
        partitioned::{CurrentThreadContext, PartitionedStore},
    };

    #[test]
    fn unique_partition() {
        let metric = metric_name!("foo");
        let mut store = PartitionedStore::new();
        store.with_partition_mut(1, |store| {
            store.counter(&metric).inc(1);
        });
        store.with_partition_mut(5, |store| {
            store.counter(&metric).inc(5);
        });

        assert_eq!(
            5,
            store.with_partition_mut(5, |store| store.counter(&metric).get())
        );
        assert_eq!(
            1,
            store.with_partition_mut(1, |store| store.counter(&metric).get())
        );
        assert_eq!(
            0,
            store.with_partition_mut(10, |store| store.counter(&metric).get())
        );
    }

    #[test]
    fn current_partition() {
        let metric = metric_name!("foo");
        let mut store = PartitionedStore::new();
        store.counter(&metric).inc(7);

        CurrentThreadContext::set(4);

        store.counter(&metric).inc(1);
        store.counter(&metric).inc(5);

        assert_eq!(6, store.counter_val(&metric));
        CurrentThreadContext::toggle(None);
        assert_eq!(7, store.counter_val(&metric));
    }

    #[test]
    fn empty() {
        let mut store = PartitionedStore::default();
        assert!(store.is_empty());
        store.counter(&metric_name!("foo")).inc(1);

        assert!(!store.is_empty());
    }

    #[test]
    fn len() {
        let mut store = PartitionedStore::new();
        assert_eq!(0, store.len());

        store.counter(metric_name!("foo")).inc(1);
        CurrentThreadContext::set(4);
        store.counter(metric_name!("foo")).inc(1);

        // one metric in partition 4, another one in default. Even that they are the same,
        // partitioned store cannot distinguish between them
        assert_eq!(2, store.len());
    }

    #[test]
    fn merge() {
        let mut store1 = PartitionedStore::new();
        let mut store2 = PartitionedStore::new();
        store1.with_partition_mut(1, |store| store.counter(counter!("foo")).inc(1));
        store2.with_partition_mut(1, |store| store.counter(counter!("foo")).inc(1));
        store1.with_partition_mut(2, |store| store.counter(counter!("foo")).inc(2));
        store2.with_partition_mut(2, |store| store.counter(counter!("foo")).inc(2));

        store1.counter(counter!("foo")).inc(3);
        store2.counter(counter!("foo")).inc(3);

        store1.merge(store2);
        assert_eq!(
            2,
            store1
                .with_partition(1, |store| store.counter_val(counter!("foo")))
                .unwrap()
        );
        assert_eq!(
            4,
            store1
                .with_partition(2, |store| store.counter_val(counter!("foo")))
                .unwrap()
        );
        assert_eq!(6, store1.counter_val(counter!("foo")));
    }
}
