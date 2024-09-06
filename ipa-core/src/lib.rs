#![deny(clippy::pedantic, clippy::clone_on_ref_ptr)]
// The following warnings are too noisy for us and having them enabled leads to polluting the
// code with allow annotations. Disabling them once per project here
#![allow(clippy::similar_names)]
#![allow(clippy::module_name_repetitions)]
// In unit tests, it is ok to use methods discouraged to use in prod code. Most of the time it is
// because of performance implications which shouldn't be a concern for unit testing.
#![cfg_attr(test, allow(clippy::disallowed_methods))]

#[cfg(any(feature = "cli", feature = "web-app"))]
pub mod cli;
#[cfg(feature = "web-app")]
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
mod seq_join;
mod serde;
pub mod sharding;
mod utils;

pub use app::{AppConfig, HelperApp, Setup as AppSetup};

extern crate core;
#[cfg(all(feature = "shuttle", test))]
extern crate shuttle_crate as shuttle;

#[cfg(all(feature = "shuttle", test))]
pub(crate) mod sync {
    pub use shuttle::sync::{Arc, Mutex, MutexGuard, Weak};
    pub mod atomic {
        pub use shuttle::sync::atomic::{AtomicUsize, Ordering};
    }
}

#[cfg(not(all(feature = "shuttle", test)))]
pub(crate) mod sync {
    pub use std::sync::{Arc, Mutex, MutexGuard, Weak};
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

#[cfg(all(feature = "multi-threading", feature = "shuttle"))]
pub(crate) mod shim {
    use std::any::Any;

    use shuttle_crate::future::JoinError;

    /// There is currently an API mismatch between Tokio and Shuttle `JoinError` implementations.
    /// This trait brings them closer together, until it is addressed
    pub trait Tokio: Sized {
        fn try_into_panic(self) -> Result<Box<dyn Any + Send + 'static>, Self>;
    }

    impl Tokio for JoinError {
        fn try_into_panic(self) -> Result<Box<dyn Any + Send + 'static>, Self> {
            Err(self) // Shuttle `JoinError` does not wrap panics
        }
    }
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

    pub fn run_with<F, Fut, T, const ITER: usize>(f: F) -> T
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = T>,
    {
        tokio::runtime::Builder::new_multi_thread()
            // enable_all() is common to use to build Tokio runtime, but it enables both IO and time drivers.
            // IO driver is not compatible with Miri (https://github.com/rust-lang/miri/issues/2057) which we use to
            // sanitize our tests, so this runtime only enables time driver.
            .enable_time()
            .build()
            .unwrap()
            .block_on(f())
    }

    pub fn run<F, Fut, T>(f: F) -> T
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = T>,
    {
        run_with::<_, _, _, 1>(f)
    }
}

pub const CRATE_NAME: &str = env!("CARGO_CRATE_NAME");

#[macro_export]
macro_rules! const_assert {
    ($x:expr $(,)?) => {
        const _: () = assert!($x, stringify!($x));
    };
    ($x:expr, $msg:expr $(,)?) => {
        const _: () = assert!($x, $msg);
    };
}

#[macro_export]
macro_rules! const_assert_eq {
    ($x:expr, $y:expr $(,)?) => {
        $crate::const_assert!($x == $y);
    };
    ($x:expr, $y:expr, $msg:expr $(,)?) => {
        $crate::const_assert!($x == $y, $msg);
    };
}

macro_rules! mutually_incompatible {
    ($feature1:literal,$feature2:literal) => {
        #[cfg(all(feature = $feature1, feature = $feature2))]
        compile_error!(concat!(
            "feature \"",
            $feature1,
            "\" and feature \"",
            $feature2,
            "\" can't be enabled at the same time"
        ));
    };
}

mutually_incompatible!("in-memory-infra", "real-world-infra");
