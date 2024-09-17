use std::{
    fmt::{Debug, Display, Formatter},
    hash::Hasher,
};

use ipa_metrics::LabelValue;
use rustc_hash::FxHasher;
use serde::Deserialize;

use crate::{Gate, Step, StepNarrow};

pub mod labels {
    pub const STEP_NARROWED: &str = "step.narrowed";
    pub const STEP: &str = "step";
}

/// A descriptive representation of a unique step in protocol execution.
///
/// This gathers context from multiple layers of execution. Each stage of execution has its
/// own description of the different steps it takes.  Individual components are identified
/// using an implementation of `Step`.  This type combines those with the identifiers from
/// outer functional layers to form a unique, descriptive string.
///
/// This allows each stage of execution to be uniquely identified, while still
/// enabling functional decomposition.
///
/// Underneath, this just takes the string value of each step and concatenates them,
/// with a "/" between each component.
///
/// For example, you might have a high-level process with three steps "a", "b", and "c".
/// Step "a" comprises two actions "x" and "y", but "b" and "c" are atomic actions.
/// Step "a" would be executed with a context identifier of "protocol/a", which it
///  would `narrow()` into "protocol/a/x" and "protocol/a/y" to produce a final set
/// of identifiers: ".../a/x", ".../a/y", ".../b", and ".../c".
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(from = "&str")]
pub struct Descriptive {
    id: String,
}

impl Descriptive {
    pub fn new(n: impl AsRef<str>) -> Self {
        Self {
            id: String::from(n.as_ref()),
        }
    }
}

impl Gate for Descriptive {}

impl Default for Descriptive {
    fn default() -> Self {
        Self::new("protocol")
    }
}

impl AsRef<str> for Descriptive {
    fn as_ref(&self) -> &str {
        self.id.as_str()
    }
}

impl From<&str> for Descriptive {
    fn from(id: &str) -> Self {
        let id = id.strip_prefix('/').unwrap_or(id);
        Descriptive { id: id.to_owned() }
    }
}

impl Display for Descriptive {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.id)
    }
}

impl Debug for Descriptive {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("gate=")?;
        <Self as Display>::fmt(self, f)
    }
}

impl<S: Step + ?Sized> StepNarrow<S> for Descriptive {
    /// Narrow the scope of the step identifier.
    /// # Panics
    /// In a debug build, this checks that the same refine call isn't run twice and that the string
    /// value of the step doesn't include '/' (which would lead to a bad outcome).
    fn narrow(&self, step: &S) -> Self {
        #[cfg(debug_assertions)]
        {
            let s = String::from(step.as_ref());
            assert!(!s.contains('/'), "The string for a step cannot contain '/'");
        }

        let id = format!("{}/{}", self.id, step.as_ref());

        Self { id }
    }
}

impl LabelValue for Descriptive {
    fn hash(&self) -> u64 {
        fn hash_str(input: &str) -> u64 {
            let mut hasher = FxHasher::default();
            hasher.write(input.as_bytes());
            hasher.finish()
        }

        hash_str(self.as_ref())
    }

    fn boxed(&self) -> Box<dyn LabelValue> {
        Box::new(self.clone())
    }
}
