use std::{borrow::Borrow, hash::BuildHasher};

use hashbrown::hash_map::RawEntryMut;
use rustc_hash::FxBuildHasher;

use crate::{key::OwnedMetricName, kind::CounterValue, MetricName};

/// A basic store. Currently only supports counters.
/// Counters and other metrics are stored to optimize writes. That means, one lookup
/// per write. The cost of assembling the total count across all dimensions is absorbed
/// by readers
#[derive(Clone, Debug)]
pub struct Store {
    counters: hashbrown::HashMap<OwnedMetricName, CounterValue, FxBuildHasher>,
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            counters: hashbrown::HashMap::with_hasher(FxBuildHasher),
        }
    }

    pub fn merge(&mut self, other: Self) {
        for (k, v) in other.counters {
            let hash_builder = self.counters.hasher();
            let hash = hash_builder.hash_one(&k);
            *self
                .counters
                .raw_entry_mut()
                .from_hash(hash, |other| other.eq(&k))
                .or_insert(k, 0)
                .1 += v;
        }
    }

    pub fn counter<'a, const LABELS: usize, B: Borrow<MetricName<'a, LABELS>>>(
        &'a mut self,
        key: B,
    ) -> CounterHandle<'a, LABELS> {
        let key = key.borrow();
        let hash_builder = self.counters.hasher();
        let hash = hash_builder.hash_one(key);
        let entry = self
            .counters
            .raw_entry_mut()
            .from_hash(hash, |key_found| key_found.eq(key));
        match entry {
            RawEntryMut::Occupied(slot) => CounterHandle {
                val: slot.into_mut(),
            },
            RawEntryMut::Vacant(slot) => {
                let (_, val) = slot.insert_hashed_nocheck(hash, key.to_owned(), Default::default());
                CounterHandle { val }
            }
        }
    }

    /// Returns the value for the specified metric taking into account
    /// its dimensionality. That is (foo, dim1 = 1, dim2 = 2) will be
    /// different from (foo, dim1 = 1).
    /// The cost of this operation is `O(N*M)` where `N` - number of unique metrics
    /// registered in this store and `M` number of dimensions.
    ///
    /// Note that the cost can be improved if it ever becomes a bottleneck by
    /// creating a specialized two-level map (metric -> label -> value).
    pub fn counter_val<'a, const LABELS: usize, B: Borrow<MetricName<'a, LABELS>>>(
        &'a self,
        key: B,
    ) -> CounterValue {
        let key = key.borrow();
        let mut answer = 0;
        for (metric, value) in &self.counters {
            if metric.partial_match(key) {
                answer += value;
            }
        }

        answer
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.counters.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub struct CounterHandle<'a, const LABELS: usize> {
    val: &'a mut CounterValue,
}

impl<const LABELS: usize> CounterHandle<'_, LABELS> {
    pub fn inc(&mut self, inc: CounterValue) {
        *self.val += inc;
    }

    pub fn get(&self) -> CounterValue {
        *self.val
    }
}

#[cfg(test)]
mod tests {
    use std::hash::{DefaultHasher, Hash, Hasher};

    use crate::{counter, metric_name, store::Store, LabelValue};

    impl LabelValue for &'static str {
        fn hash(&self) -> u64 {
            // TODO: use fast hashing here
            let mut hasher = DefaultHasher::default();
            Hash::hash(self, &mut hasher);

            hasher.finish()
        }

        fn boxed(&self) -> Box<dyn LabelValue> {
            Box::new(*self)
        }
    }

    #[test]
    fn counter() {
        let mut store = Store::default();
        let name = metric_name!("foo");
        {
            let mut handle = store.counter(&name);
            assert_eq!(0, handle.get());
            handle.inc(3);
            assert_eq!(3, handle.get());
        }

        {
            store.counter(&name).inc(0);
            assert_eq!(3, store.counter(&name).get());
        }
    }

    #[test]
    fn with_labels() {
        let mut store = Store::default();
        let valid_name = metric_name!("foo", "h1" => &1, "h2" => &"2");
        let wrong_name = metric_name!("foo", "h1" => &2, "h2" => &"2");
        store.counter(&valid_name).inc(2);

        assert_eq!(2, store.counter(&valid_name).get());
        assert_eq!(0, store.counter(&wrong_name).get());
    }

    #[test]
    fn merge() {
        let mut store1 = Store::default();
        let mut store2 = Store::default();
        let foo = metric_name!("foo", "h1" => &1, "h2" => &"2");
        let bar = metric_name!("bar", "h2" => &"2");
        let baz = metric_name!("baz");
        store1.counter(&foo).inc(2);
        store2.counter(&foo).inc(1);

        store1.counter(&bar).inc(7);
        store2.counter(&baz).inc(3);

        store1.merge(store2);

        assert_eq!(3, store1.counter(&foo).get());
        assert_eq!(7, store1.counter(&bar).get());
        assert_eq!(3, store1.counter(&baz).get());
    }

    #[test]
    fn counter_value() {
        let mut store = Store::default();
        store
            .counter(counter!("foo", "h1" => &1, "h2" => &"1"))
            .inc(1);
        store
            .counter(counter!("foo", "h1" => &1, "h2" => &"2"))
            .inc(1);
        store
            .counter(counter!("foo", "h1" => &2, "h2" => &"1"))
            .inc(1);
        store
            .counter(counter!("foo", "h1" => &2, "h2" => &"2"))
            .inc(1);
        store
            .counter(counter!("bar", "h1" => &1, "h2" => &"1"))
            .inc(3);

        assert_eq!(4, store.counter_val(counter!("foo")));
        assert_eq!(
            1,
            store.counter_val(&counter!("foo", "h1" => &1, "h2" => &"2"))
        );
        assert_eq!(2, store.counter_val(&counter!("foo", "h1" => &1)));
        assert_eq!(2, store.counter_val(&counter!("foo", "h2" => &"2")));
    }
}
