use std::fmt::{Debug, Display, Formatter};

use super::{Step, StepNarrow};
#[cfg(feature = "step-trace")]
use crate::telemetry::{labels::STEP, metrics::STEP_NARROWED};

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
#[derive(Clone, Hash, PartialEq, Eq)]
#[cfg_attr(
    feature = "enable-serde",
    derive(serde::Deserialize),
    serde(from = "&str")
)]
pub struct Descriptive {
    id: String,
}

impl Display for Descriptive {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
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

        let mut id = self.id.clone() + "/";
        #[cfg(all(feature = "step-trace", feature = "in-memory-infra"))]
        {
            id += [std::any::type_name::<S>(), "::"].concat().as_ref();
        }
        id += step.as_ref();
        #[cfg(feature = "step-trace")]
        {
            metrics::increment_counter!(STEP_NARROWED, STEP => id.clone());
        }

        Self { id }
    }
}

impl Default for Descriptive {
    // TODO(mt): this should might be better if it were to be constructed from
    // a QueryId rather than using a default.
    fn default() -> Self {
        Self {
            id: String::from("protocol"),
        }
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

impl Debug for Descriptive {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "step={}", self.id)
    }
}
