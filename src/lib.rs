#![deny(clippy::pedantic, clippy::clone_on_ref_ptr)]
// The following warnings are too noisy for us and having them enabled leads to polluting the
// code with allow annotations. Disabling them once per project here
#![allow(clippy::similar_names)]
#![allow(clippy::module_name_repetitions)]

pub mod bits;
pub mod chunkscan;
#[cfg(feature = "cli")]
pub mod cli;
pub mod error;
pub mod ff;
pub mod helpers;
pub mod hpke;
#[cfg(feature = "web-app")]
pub mod net;
pub mod protocol;
pub mod query;
pub mod secret_sharing;
pub mod telemetry;
#[cfg(feature = "enable-serde")]
pub mod uri;

#[cfg(any(test, feature = "test-fixture"))]
pub mod test_fixture;

mod tests;

#[cfg(all(feature = "shuttle", test))]
extern crate shuttle_crate as shuttle;

#[cfg(all(feature = "shuttle", test))]
pub(crate) mod sync {
    pub use shuttle::sync::{Arc, Mutex, Once, Weak};
    pub mod atomic {
        pub use shuttle::sync::atomic::{AtomicUsize, Ordering};
    }
}

#[cfg(not(all(feature = "shuttle", test)))]
pub(crate) mod sync {
    pub use std::sync::{Arc, Mutex, Once, Weak};
    pub mod atomic {
        pub use std::sync::atomic::{AtomicUsize, Ordering};
    }
}

#[cfg(all(feature = "shuttle", test))]
pub(crate) mod rand {
    pub use shuttle::rand::{thread_rng, Rng, RngCore};

    /// TODO: shuttle does not re-export `CryptoRng`. The only reason it works is because IPA uses
    /// the same version of `rand`.
    pub use rand::CryptoRng;
}

#[cfg(not(all(feature = "shuttle", test)))]
pub(crate) mod rand {
    pub use rand::{thread_rng, CryptoRng, Rng, RngCore};
}

#[cfg(all(feature = "shuttle", test))]
pub(crate) mod task {
    pub use shuttle::future::JoinHandle;
}

#[cfg(not(all(feature = "shuttle", test)))]
pub(crate) mod task {
    pub use tokio::task::JoinHandle;
}
