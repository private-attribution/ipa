//! Metric names supported by this crate.
//!
//! Providing a good use for metrics is a tradeoff between
//! performance and ergonomics. Flexible metric engines support
//! dynamic names, like "bytes.sent.{ip}" or "cpu.{core}.instructions"
//! but that comes with a significant performance cost.
//! String interning helps to mitigate this on the storage site
//! but callsites need to allocate those at every call.
//!
//! IPA metrics can be performance sensitive. There are counters
//! incremented on every send and receive operation, so they need
//! to be fast. For this reason, dynamic metric names are not supported.
//! Metric name can only be a string, known at compile time.
//!
//! However, it is not flexible enough. Most metrics have dimensions
//! attached to them. IPA example is `bytes.sent` metric with step breakdown.
//! It is very useful to know the required throughput per circuit.
//!
//! This metric engine supports up to 5 dimensions attached to every metric,
//! again trying to strike a good balance between performance and usability.

use std::borrow::Borrow;
use std::hash::{Hash, Hasher};

pub(super) use OwnedName as OwnedMetricName;
pub use Name as MetricName;

/// Metric name that is created at callsite on each metric invocation.
/// For this reason, it is performance sensitive - it tries to borrow
/// whatever it can from callee stack.
#[derive(Debug)]
pub struct Name<const LABELS: usize = 0> {
    key: &'static str,
    // labels: [Option<(&'static str, &'tag dyn LabelValue)>; LABELS],
}

impl <const LABELS: usize> Name<LABELS> {

    /// [`ToOwned`] trait does not work because of
    /// extra [`Borrow`] requirement
    pub(super) fn to_owned(&self) -> OwnedName {
        OwnedName {
            key: self.key
        }
    }
}

/// Same as [`Name`], but intended for internal use. This is an owned
/// version of it, that does not borrow anything from outside.
/// This is the key inside metric stores which are simple hashmaps.
#[derive(Debug)]
pub(super) struct OwnedName {
    key: &'static str
}

impl <const LABELS: usize> Hash for Name<LABELS> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        /// keep in mind that the following will cause collision
        /// "foo", [1, 0]
        /// "foo", [0, 1]
        ///
        /// so hashing labels needs to account for that
        state.write(self.key.as_bytes())
    }
}

impl From<&'static str> for Name<0> {
    fn from(value: &'static str) -> Self {
        Self {
            key: value
        }
    }
}

impl <const LABELS: usize> PartialEq<Name<LABELS>> for &OwnedName {
    fn eq(&self, other: &Name<LABELS>) -> bool {
        self.key == other.key
    }
}

impl Hash for OwnedName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        /// keep in mind that the following will cause collision
        /// "foo", [1, 0]
        /// "foo", [0, 1]
        ///
        /// so hashing labels needs to account for that
        state.write(self.key.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Borrow;
    use std::hash::{DefaultHasher, Hash, Hasher};
    use crate::key::{Name, OwnedName};

    fn compute_hash<V: Hash>(value: V) -> u64 {
        let mut hasher = DefaultHasher::default();
        value.hash(&mut hasher);

        hasher.finish()
    }

    #[test]
    fn eq() {
        let name = Name::from("foo");
        assert_eq!(&name.to_owned(), name);
    }

    #[test]
    fn hash_eq() {
        let a = Name::from("foo");
        let b = Name::from("foo");
        assert_eq!(compute_hash(&a), compute_hash(b));
        assert_eq!(compute_hash(&a), compute_hash(a.to_owned()));
    }

    #[test]
    fn not_eq() {
        let foo = Name::from("foo");
        let bar = Name::from("bar");
        assert_ne!(&foo.to_owned(), bar);
    }

    #[test]
    fn hash_not_eq() {
        let foo = Name::from("foo");
        let bar = Name::from("bar");
        assert_ne!(compute_hash(&foo), compute_hash(&bar));
        assert_ne!(compute_hash(foo), compute_hash(bar.to_owned()));
    }
}
