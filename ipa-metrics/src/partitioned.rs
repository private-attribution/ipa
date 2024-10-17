use std::{borrow::Borrow, cell::Cell};

use hashbrown::hash_map::Entry;
use rustc_hash::FxBuildHasher;

use crate::{
    kind::CounterValue,
    store::{CounterHandle, Store},
    MetricName,
};

/// Each partition is a unique 16 byte value.
pub type Partition = u128;

pub fn set_partition(new: Partition) {
    PARTITION.set(Some(new));
}

pub fn set_or_unset_partition(new: Option<Partition>) {
    PARTITION.set(new);
}

pub fn current_partition() -> Option<Partition> {
    PARTITION.get()
}

thread_local! {
    static PARTITION: Cell<Option<Partition>> = Cell::new(None);
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
    inner: hashbrown::HashMap<Partition, Store, FxBuildHasher>,
    default_store: Store,
}

impl Default for PartitionedStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PartitionedStore {
    pub const fn new() -> Self {
        Self {
            inner: hashbrown::HashMap::with_hasher(FxBuildHasher),
            default_store: Store::new(),
        }
    }

    pub fn with_current_partition<F: FnOnce(&mut Store) -> T, T>(&mut self, f: F) -> T {
        let mut store = self.get_mut(current_partition());
        f(&mut store)
    }

    pub fn with_partition<F: FnOnce(&Store) -> T, T>(
        &self,
        partition: Partition,
        f: F,
    ) -> Option<T> {
        let store = self.inner.get(&partition);
        store.map(f)
    }

    pub fn with_partition_mut<F: FnOnce(&mut Store) -> T, T>(
        &mut self,
        partition: Partition,
        f: F,
    ) -> T {
        let mut store = self.get_mut(Some(partition));
        f(&mut store)
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty() && self.default_store.is_empty()
    }

    pub fn merge(&mut self, other: Self) {
        for (partition, store) in other.inner {
            self.get_mut(Some(partition)).merge(store);
        }
        self.default_store.merge(other.default_store);
    }

    pub fn counter_value<B: Borrow<MetricName>>(&self, name: B) -> CounterValue {
        let name = name.borrow();
        if let Some(partition) = current_partition() {
            self.inner
                .get(&partition)
                .map(|store| store.counter_value(name))
                .unwrap_or_default()
        } else {
            self.default_store.counter_value(name)
        }
    }

    pub fn counter<const LABELS: usize>(
        &mut self,
        key: &MetricName<'_, LABELS>,
    ) -> CounterHandle<'_, LABELS> {
        if let Some(partition) = current_partition() {
            self.inner
                .entry(partition)
                .or_insert_with(|| Store::default())
                .counter(key)
        } else {
            self.default_store.counter(key)
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len() + self.default_store.len()
    }

    fn get_mut(&mut self, partition: Option<u128>) -> &mut Store {
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
        metric_name,
        partitioned::{set_partition, PartitionedStore},
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
        set_partition(4);

        store.with_current_partition(|store| {
            store.counter(&metric).inc(1);
        });
        store.with_current_partition(|store| {
            store.counter(&metric).inc(5);
        });

        assert_eq!(
            6,
            store.with_current_partition(|store| store.counter(&metric).get())
        );
    }

    #[test]
    fn empty() {
        let mut store = PartitionedStore::new();
        store.with_current_partition(|store| {
            store.counter(&metric_name!("foo")).inc(1);
        });

        assert!(!store.is_empty());
    }

    #[test]
    fn len() {
        let mut store = PartitionedStore::new();
        store.with_current_partition(|store| {
            store.counter(&metric_name!("foo")).inc(1);
        });
        set_partition(4);
        store.with_current_partition(|store| {
            store.counter(&metric_name!("foo")).inc(1);
        });

        // one metric in partition 4, another one in default. Even that they are the same,
        // partitioned store cannot distinguish between them
        assert_eq!(2, store.len());
    }
}
