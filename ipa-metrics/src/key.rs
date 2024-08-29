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
};

pub use Name as MetricName;
pub(super) use OwnedName as OwnedMetricName;

use crate::{
    label::{Label, OwnedLabel, MAX_LABELS},
};

#[macro_export]
macro_rules! metric_name {
    // Match when two key-value pairs are provided
    // TODO: enforce uniqueness at compile time
    ($metric:expr, $l1:expr => $v1:expr, $l2:expr => $v2:expr) => {{
        let labels = {
            crate::key::UniqueElements::enforce_unique([
                Label {
                    name: $l1,
                    val: $v1,
                },
                Label {
                    name: $l2,
                    val: $v2,
                },
            ])
        };
        crate::key::NameWithTwoLabels::from_parts($metric, labels)
    }};
    // Match when one key-value pair is provided
    ($metric:expr, $l1:expr => $v1:expr) => {{
        crate::key::NameWithLabel::from_parts(
            $metric,
            [Label {
                name: $l1,
                val: $v1,
            }],
        )
    }}; // // Match when no key-value pairs are provided
        // ($metric:expr) => {{
        //     debug!("{}", $metric);
        //     // Here you can call the actual function that increments the counter
        //     // increment_counter($metric);
        // }};
}

/// Metric name that is created at callsite on each metric invocation.
/// For this reason, it is performance sensitive - it tries to borrow
/// whatever it can from callee stack.
#[derive(Debug)]
pub struct Name<'lv, const LABELS: usize = 0> {
    key: &'static str,
    labels: [Label<'lv>; LABELS],
}

pub type NameWithLabel<'lv> = Name<'lv, 1>;
pub type NameWithTwoLabels<'lv> = Name<'lv, 2>;

impl<'lv, const LABELS: usize> Name<'lv, LABELS> {
    const _NAME: () = assert!(LABELS <= MAX_LABELS);
    pub const fn from_parts(key: &'static str, labels: [Label<'lv>; LABELS]) -> Self {
        assert!(
            LABELS <= MAX_LABELS,
            "Maximum 5 labels per metric is supported"
        );

        Self { key, labels }
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
#[derive(Debug)]
pub(super) struct OwnedName {
    key: &'static str,
    labels: [Option<OwnedLabel>; 5],
}

impl<const LABELS: usize> Hash for Name<'_, LABELS> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(self.key.as_bytes());
        for label in &self.labels {
            label.hash(state)
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
    fn enforce_unique(self) -> Self;
}

impl UniqueElements for [Label<'_>; 2] {
    fn enforce_unique(self) -> Self {
        if self[0].name == self[1].name {
            panic!("label names must be unique")
        }

        self
    }
}

impl<'a, 'b, const LABELS: usize> PartialEq<Name<'a, LABELS>> for &'b OwnedName {
    fn eq(&self, other: &Name<LABELS>) -> bool {
        self.key == other.key
            && iter::zip(&self.labels, &other.labels).all(|(a, b)| {
                if let Some(a) = a {
                    a.name == b.name && a.val.hash() == b.val.hash()
                } else {
                    false
                }
            })
    }
}

impl Hash for OwnedName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(self.key.as_bytes());
        for label in &self.labels {
            if let Some(label) = label {
                label.hash(state)
            }
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
}
