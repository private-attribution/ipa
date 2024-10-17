use std::hash::{BuildHasher, Hash, Hasher};

use hashbrown::hash_map::RawEntryMut;
use rustc_hash::FxBuildHasher;

use crate::{
    key::{OwnedMetricName, OwnedName},
    kind::CounterValue,
    MetricName,
};

/// A basic store. Currently only supports counters.
#[derive(Clone, Debug)]
pub struct Store {
    // Counters and other metrics are stored to optimize writes. That means, one lookup
    // per write. The cost of assembling the total count across all dimensions is absorbed
    // by readers
    counters: hashbrown::HashMap<OwnedMetricName, CounterValue, FxBuildHasher>,
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    pub const fn new() -> Self {
        Self {
            counters: hashbrown::HashMap::with_hasher(FxBuildHasher),
        }
    }

    pub(crate) fn merge(&mut self, other: Self) {
        for (k, v) in other.counters {
            let hash = compute_hash(self.counters.hasher(), &k);
            *self
                .counters
                .raw_entry_mut()
                .from_hash(hash, |other| other.eq(&k))
                .or_insert(k, 0)
                .1 += v;
        }
    }

    pub fn is_empty(&self) -> bool {
        self.counters.is_empty()
    }
}

impl Store {
    pub fn counter<const LABELS: usize>(
        &mut self,
        key: &MetricName<'_, LABELS>,
    ) -> CounterHandle<'_, LABELS> {
        let hash = compute_hash(self.counters.hasher(), &key);
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

    /// Returns the value for the specified metric across all dimensions.
    /// The cost of this operation is `O(N*M)` where `N` - number of unique metrics
    /// and `M` - number of all dimensions across all metrics.
    ///
    /// Note that the cost can be improved if it ever becomes a bottleneck by
    /// creating a specialized two-level map (metric -> label -> value).
    pub fn counter_value(&self, key: &MetricName<'_>) -> CounterValue {
        let mut answer = 0;
        for (metric, value) in &self.counters {
            if metric.key == key.key {
                answer += value
            }
        }

        answer
    }

    pub fn counters(&self) -> impl Iterator<Item = (&OwnedName, CounterValue)> {
        self.counters.iter().map(|(key, value)| (key, *value))
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

fn compute_hash<B: BuildHasher, K: Hash + ?Sized>(hash_builder: &B, key: &K) -> u64 {
    let mut hasher = hash_builder.build_hasher();
    key.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use std::hash::{DefaultHasher, Hash, Hasher};

    use crate::{metric_name, store::Store, LabelValue};

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
            .counter(&metric_name!("foo", "h1" => &1, "h2" => &"1"))
            .inc(1);
        store
            .counter(&metric_name!("foo", "h1" => &1, "h2" => &"2"))
            .inc(1);
        store
            .counter(&metric_name!("foo", "h1" => &2, "h2" => &"1"))
            .inc(1);
        store
            .counter(&metric_name!("foo", "h1" => &2, "h2" => &"2"))
            .inc(1);

        assert_eq!(4, store.counter_value(&metric_name!("foo")));
    }
}
