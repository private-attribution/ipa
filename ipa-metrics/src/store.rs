use std::hash::{BuildHasher, Hash, Hasher};
use std::mem;
use std::num::{NonZeroU64, NonZeroUsize};
use hashbrown::hash_map::RawEntryMut;
use rustc_hash::{FxBuildHasher, FxHasher};
use crate::key::OwnedMetricName;
use crate::kind::CounterValue;
use crate::MetricName;

/// A basic store. Currently only supports counters.
#[derive(Default)]
struct Store {
    counters: hashbrown::HashMap<OwnedMetricName, CounterValue, FxBuildHasher>
}


impl Store {
    pub fn counter<const LABELS: usize, N: Into<MetricName<LABELS>>>(&mut self, key: N) -> CounterHandle<'_, LABELS> {
        let key = key.into();
        let hash = compute_hash(self.counters.hasher(), &key);
        let entry= self.counters.raw_entry_mut().from_hash(hash, |key_found| key_found.eq(&key));
        match entry {
            RawEntryMut::Occupied(slot) => {
                CounterHandle {
                    val: slot.into_mut()
                }
            }
            RawEntryMut::Vacant(slot) => {
                let (_, val) = slot.insert_hashed_nocheck(hash, key.to_owned(), Default::default());
                CounterHandle {
                    val
                }
            }
        }
    }
}

struct CounterHandle<'a, const LABELS: usize> {
    val: &'a mut CounterValue
}

impl <const LABELS: usize> CounterHandle<'_, LABELS> {
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
    use std::num::NonZeroU64;
    use crate::store::Store;

    #[test]
    fn counter() {
        let mut store = Store::default();
        let name = "foo";
        {
            let mut handle = store.counter(name);
            assert_eq!(0, handle.get());
            handle.inc(3);
            assert_eq!(3, handle.get());
        }

        {
            store.counter(name).inc(0);
            assert_eq!(3, store.counter(name).get());
        }
    }

    // test that checks label values hash colliding does not lead to collision in keys
}
