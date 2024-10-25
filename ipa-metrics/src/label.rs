use std::{
    fmt::{Debug, Display, Formatter},
    hash::{Hash, Hasher},
};

use rustc_hash::FxHasher;

pub const MAX_LABELS: usize = 5;

/// Provides a fast, non-collision resistant implementation of [`Hasher`]
/// for label values. T
///
/// [`Hasher`]: std::hash::Hasher
#[must_use]
pub fn label_hasher() -> impl Hasher {
    FxHasher::default()
}

/// Dimension value (or label value) must be sendable to another thread
/// and there must be a way to show it
pub trait LabelValue: Display + Send {
    /// Creates a unique hash for this value.
    /// It is easy to create collisions, so better avoid them,
    /// by assigning a unique integer to each value
    ///
    /// Note that this value is used for uniqueness check inside
    /// metric stores
    fn hash(&self) -> u64;

    /// Creates an owned copy of this value. Dynamic dispatch
    /// is required, because values are stored in a generic store
    /// that can't be specialized for value types.
    fn boxed(&self) -> Box<dyn LabelValue>;
}

impl LabelValue for u32 {
    fn hash(&self) -> u64 {
        u64::from(*self)
    }

    fn boxed(&self) -> Box<dyn LabelValue> {
        Box::new(*self)
    }
}

pub struct Label<'lv> {
    pub name: &'static str,
    pub val: &'lv dyn LabelValue,
}

impl Label<'_> {
    #[must_use]
    pub fn to_owned(&self) -> OwnedLabel {
        OwnedLabel {
            name: self.name,
            val: self.val.boxed(),
        }
    }
}

impl Debug for Label<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Label")
            .field("name", &self.name)
            .field("val", &format!("{}", self.val))
            .finish()
    }
}

impl Hash for Label<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash(&self.name, state);
        Hash::hash(&self.val.hash(), state);
    }
}

impl PartialEq for Label<'_> {
    fn eq(&self, other: &Self) -> bool {
        // name check should be fast - just pointer comparison.
        // val check is more involved with dynamic dispatch, so we can consider
        // making label immutable and storing a hash of the value in place
        self.name == other.name && self.val.hash() == other.val.hash()
    }
}

/// Same as [`Label`] but owns the values. This instance is stored
/// inside metric hashmaps as they need to own the keys.
pub struct OwnedLabel {
    pub name: &'static str,
    pub val: Box<dyn LabelValue>,
}

impl Clone for OwnedLabel {
    fn clone(&self) -> Self {
        Self {
            name: self.name,
            val: self.val.boxed(),
        }
    }
}

impl OwnedLabel {
    pub fn as_borrowed(&self) -> Label<'_> {
        Label {
            name: self.name,
            val: self.val.as_ref(),
        }
    }
}

impl Hash for OwnedLabel {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_borrowed().hash(state);
    }
}

impl Debug for OwnedLabel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedLabel")
            .field("name", &self.name)
            .field("val", &format!("{}", self.val))
            .finish()
    }
}

impl PartialEq for OwnedLabel {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.val.hash() == other.val.hash()
    }
}

impl Eq for OwnedLabel {}

#[cfg(test)]
mod tests {

    use crate::{key::compute_hash, metric_name};

    #[test]
    fn one_label() {
        let foo_1 = metric_name!("foo", "l1" => &1);
        let foo_2 = metric_name!("foo", "l1" => &2);

        assert_ne!(foo_1.to_owned(), foo_2);
        assert_ne!(compute_hash(&foo_1), compute_hash(&foo_2));
        assert_ne!(foo_2.to_owned(), foo_1);

        assert_eq!(compute_hash(&foo_1), compute_hash(foo_1.to_owned()));
    }

    #[test]
    #[should_panic(expected = "label names must be unique")]
    fn unique() {
        metric_name!("foo", "l1" => &1, "l1" => &0);
    }

    #[test]
    fn non_commutative() {
        assert_ne!(
            compute_hash(&metric_name!("foo", "l1" => &1, "l2" => &0)),
            compute_hash(&metric_name!("foo", "l1" => &0, "l2" => &1)),
        );
        assert_ne!(
            compute_hash(&metric_name!("foo", "l1" => &1)),
            compute_hash(&metric_name!("foo", "l1" => &1, "l2" => &1)),
        );
    }

    #[test]
    fn clone() {
        let metric = metric_name!("foo", "l1" => &1).to_owned();
        assert_eq!(&metric.labels().next(), &metric.labels().next().clone());
    }

    #[test]
    fn fields() {
        let metric = metric_name!("foo", "l1" => &1).to_owned();
        let label = metric.labels().next().unwrap().to_owned();

        assert_eq!(label.name, "l1");
        assert_eq!(label.val.to_string(), "1");
    }
}
