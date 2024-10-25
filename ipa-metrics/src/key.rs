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

use std::{
    array,
    hash::{Hash, Hasher},
    iter,
    iter::repeat,
};

pub use Name as MetricName;
pub(super) use OwnedName as OwnedMetricName;

use crate::label::{Label, OwnedLabel, MAX_LABELS};

#[macro_export]
macro_rules! metric_name {
    // Match when two key-value pairs are provided
    // TODO: enforce uniqueness at compile time
    ($metric:expr, $l1:expr => $v1:expr, $l2:expr => $v2:expr) => {{
        use $crate::UniqueElements;
        let labels = [
            $crate::Label {
                name: $l1,
                val: $v1,
            },
            $crate::Label {
                name: $l2,
                val: $v2,
            },
        ]
        .enforce_unique();
        $crate::MetricName::from_parts($metric, labels)
    }};
    // Match when one key-value pair is provided
    ($metric:expr, $l1:expr => $v1:expr) => {{
        $crate::MetricName::from_parts(
            $metric,
            [$crate::Label {
                name: $l1,
                val: $v1,
            }],
        )
    }};
    // Match when no key-value pairs are provided
    ($metric:expr) => {{
        $crate::MetricName::from_parts($metric, [])
    }};
}

/// Metric name that is created at callsite on each metric invocation.
/// For this reason, it is performance sensitive - it tries to borrow
/// whatever it can from callee stack.
#[derive(Debug, PartialEq)]
pub struct Name<'lv, const LABELS: usize = 0> {
    pub(super) key: &'static str,
    labels: [Label<'lv>; LABELS],
}

impl<'lv, const LABELS: usize> Name<'lv, LABELS> {
    /// Constructs this instance from key and labels.
    /// ## Panics
    /// If number of labels exceeds `MAX_LABELS`.
    pub fn from_parts<I: Into<&'static str>>(key: I, labels: [Label<'lv>; LABELS]) -> Self {
        assert!(
            LABELS <= MAX_LABELS,
            "Maximum 5 labels per metric is supported"
        );

        Self {
            key: key.into(),
            labels,
        }
    }

    /// [`ToOwned`] trait does not work because of
    /// extra [`Borrow`] requirement
    pub(super) fn to_owned(&self) -> OwnedName {
        let labels: [_; 5] = array::from_fn(|i| {
            if i < self.labels.len() {
                Some(self.labels[i].to_owned())
            } else {
                None
            }
        });

        OwnedName {
            key: self.key,
            labels,
        }
    }
}

/// Same as [`Name`], but intended for internal use. This is an owned
/// version of it, that does not borrow anything from outside.
/// This is the key inside metric stores which are simple hashmaps.
#[derive(Debug, Clone, Eq)]
pub struct OwnedName {
    pub key: &'static str,
    pub labels: [Option<OwnedLabel>; 5],
}

impl OwnedName {
    pub fn labels(&self) -> impl Iterator<Item = &OwnedLabel> {
        self.labels.iter().filter_map(|l| l.as_ref())
    }

    /// Checks that a subset of labels in `self` matches all values in `other`.
    #[must_use]
    pub fn partial_match<const LABELS: usize>(&self, other: &Name<'_, LABELS>) -> bool {
        if self.key == other.key {
            other.labels.iter().all(|l| self.find_label(l))
        } else {
            false
        }
    }

    fn find_label(&self, label: &Label<'_>) -> bool {
        self.labels().any(|l| l.as_borrowed().eq(label))
    }
}

impl<const LABELS: usize> Hash for Name<'_, LABELS> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash(&self.key, state);
        // to be consistent with `OwnedName` hashing, we need to
        // serialize labels without slice length prefix.
        for label in &self.labels {
            label.hash(state);
        }
    }
}

impl From<&'static str> for Name<'_, 0> {
    fn from(value: &'static str) -> Self {
        Self {
            key: value,
            labels: [],
        }
    }
}

pub trait UniqueElements {
    #[must_use]
    fn enforce_unique(self) -> Self;
}

impl UniqueElements for [Label<'_>; 2] {
    fn enforce_unique(self) -> Self {
        assert_ne!(self[0].name, self[1].name, "label names must be unique");

        self
    }
}

impl<'a, const LABELS: usize> PartialEq<Name<'a, LABELS>> for OwnedName {
    fn eq(&self, other: &Name<'a, LABELS>) -> bool {
        self.key == other.key
            && iter::zip(
                &self.labels,
                other.labels.iter().map(Some).chain(repeat(None)),
            )
            .all(|(a, b)| match (a, b) {
                (Some(a), Some(b)) => a.as_borrowed() == *b,
                (None, None) => true,
                _ => false,
            })
    }
}

impl PartialEq<OwnedName> for OwnedName {
    fn eq(&self, other: &OwnedName) -> bool {
        self.key == other.key && self.labels.eq(&other.labels)
    }
}

impl Hash for OwnedName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash(self.key, state);
        for label in self.labels.iter().flatten() {
            label.hash(state);
        }
    }
}

#[cfg(test)]
pub fn compute_hash<V: Hash>(value: V) -> u64 {
    let mut hasher = std::hash::DefaultHasher::default();
    value.hash(&mut hasher);

    hasher.finish()
}

#[cfg(test)]
mod tests {
    use crate::{
        key::{compute_hash, Name},
        label::Label,
    };

    #[test]
    fn eq() {
        let name = Name::from("foo");
        assert_eq!(name.to_owned(), name);
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
        assert_ne!(foo.to_owned(), bar);
    }

    #[test]
    fn hash_not_eq() {
        let foo = Name::from("foo");
        let bar = Name::from("bar");
        assert_ne!(compute_hash(&foo), compute_hash(&bar));
        assert_ne!(compute_hash(foo), compute_hash(bar.to_owned()));
    }

    #[test]
    #[should_panic(expected = "Maximum 5 labels per metric is supported")]
    fn more_than_5_labels() {
        let _ = Name::from_parts(
            "foo",
            [
                Label {
                    name: "label_1",
                    val: &1,
                },
                Label {
                    name: "label_2",
                    val: &1,
                },
                Label {
                    name: "label_3",
                    val: &1,
                },
                Label {
                    name: "label_4",
                    val: &1,
                },
                Label {
                    name: "label_5",
                    val: &1,
                },
                Label {
                    name: "label_6",
                    val: &1,
                },
            ],
        );
    }

    #[test]
    fn eq_is_consistent() {
        let a_name = metric_name!("foo", "label_1" => &1);
        let b_name = metric_name!("foo", "label_1" => &1, "label_2" => &2);

        assert_eq!(a_name, a_name);
        assert_eq!(a_name.to_owned(), a_name);

        assert_ne!(b_name.to_owned(), a_name);
        assert_ne!(a_name.to_owned(), b_name);
    }
}
