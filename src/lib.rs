#![deny(clippy::pedantic, clippy::clone_on_ref_ptr)]
// The following warnings are too noisy for us and having them enabled leads to polluting the
// code with allow annotations. Disabling them once per project here
#![allow(clippy::similar_names)]
#![allow(clippy::module_name_repetitions)]
// In unit tests, it is ok to use methods discouraged to use in prod code. Most of the time it is
// because of performance implications which shouldn't be a concern for unit testing.
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod chunkscan;
#[cfg(any(feature = "cli", feature = "web-app"))]
pub mod cli;
#[cfg(all(feature = "enable-serde", feature = "web-app"))]
pub mod config;
pub mod error;
pub mod ff;
pub mod helpers;
pub mod hpke;
#[cfg(feature = "web-app")]
pub mod net;
pub mod protocol;
pub mod query;
pub mod report;
pub mod secret_sharing;
pub mod telemetry;

#[cfg(any(test, feature = "test-fixture"))]
pub mod test_fixture;

mod app;
mod exact;
mod seq_join;
#[cfg(feature = "enable-serde")]
mod serde;

pub use app::{HelperApp, Setup as AppSetup};

extern crate core;
#[cfg(all(feature = "shuttle", test))]
extern crate shuttle_crate as shuttle;

#[cfg(all(feature = "shuttle", test))]
pub(crate) mod sync {
    pub use shuttle::sync::{Arc, Mutex, MutexGuard, Once, Weak};
    pub mod atomic {
        pub use shuttle::sync::atomic::{AtomicUsize, Ordering};
    }
}

#[cfg(not(all(feature = "shuttle", test)))]
pub(crate) mod sync {
    pub use std::sync::{Arc, Mutex, MutexGuard, Once, Weak};
    pub mod atomic {
        pub use std::sync::atomic::{AtomicUsize, Ordering};
    }
}

#[cfg(all(feature = "shuttle", test))]
pub(crate) mod rand {
    /// TODO: shuttle does not re-export `CryptoRng`. The only reason it works is because IPA uses
    /// the same version of `rand`.
    pub use rand::CryptoRng;
    pub use shuttle::rand::{thread_rng, Rng, RngCore};
}

#[cfg(not(all(feature = "shuttle", test)))]
pub(crate) mod rand {
    pub use rand::{thread_rng, CryptoRng, Rng, RngCore};
}

#[cfg(all(feature = "shuttle", test))]
pub(crate) mod task {
    pub use shuttle::future::{JoinError, JoinHandle};
}

#[cfg(not(all(feature = "shuttle", test)))]
pub(crate) mod task {
    pub use tokio::task::{JoinError, JoinHandle};
}

#[cfg(all(feature = "shuttle", test))]
pub(crate) mod test_executor {
    use std::future::Future;

    pub fn run<F, Fut>(f: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()>,
    {
        run_with::<_, _, 32>(f);
    }

    pub fn run_with<F, Fut, const ITER: usize>(f: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()>,
    {
        shuttle::check_random(move || shuttle::future::block_on(f()), ITER);
    }
}

#[cfg(all(test, unit_test, not(feature = "shuttle")))]
pub(crate) mod test_executor {
    use std::future::Future;

    pub fn run_with<F, Fut, const ITER: usize>(f: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()>,
    {
        run(f);
    }

    pub fn run<F, Fut>(f: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()>,
    {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f());
    }
}

#[cfg(all(feature = "in-memory-infra", feature = "real-world-infra"))]
compile_error!("feature \"in-memory-infra\" and feature \"real-world-infra\" cannot be enabled at the same time");

#[cfg(all(feature = "compact-gate", feature = "descriptive-date"))]
compile_error!(
    "feature \"compact-gate\" and feature \"descriptive-gate\" cannot be enabled at the same time"
);

#[cfg(all(not(feature = "compact-gate"), not(feature = "descriptive-gate")))]
compile_error!("feature \"compact-gate\" or \"descriptive-gate\" must be enabled");
