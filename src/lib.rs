#![deny(clippy::pedantic, clippy::clone_on_ref_ptr)]
// The following warnings are too noisy for us and having them enabled leads to polluting the
// code with allow annotations. Disabling them once per project here
#![allow(clippy::similar_names)]
#![allow(clippy::module_name_repetitions)]

pub mod chunkscan;
pub mod cli;
pub mod error;
pub mod ff;
pub mod helpers;
pub mod net;
pub mod protocol;
pub mod secret_sharing;
pub mod telemetry;

#[cfg(any(test, feature = "test-fixture"))]
pub mod test_fixture;
