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
pub mod utils;

pub use app::{AppConfig, HelperApp, Setup as AppSetup};
pub use utils::NonZeroU32PowerOfTwo;

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
    pub use shuttle::future::JoinError;
}

#[cfg(feature = "shuttle")]
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
    #[allow(unused_imports)]
    pub use tokio::task::{JoinError, JoinHandle};
}

#[cfg(not(feature = "shuttle"))]
pub mod executor {
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::{
        runtime::{Handle, Runtime},
        task::JoinHandle,
    };

    /// In prod we use Tokio scheduler, so this struct just wraps
    /// its runtime handle and mimics the standard executor API.
    /// The name was chosen to avoid clashes with tokio runtime
    /// when importing it
    #[derive(Clone)]
    pub struct IpaRuntime(Handle);

    /// Wrapper around Tokio's [`JoinHandle`]
    #[pin_project::pin_project]
    pub struct IpaJoinHandle<T>(#[pin] JoinHandle<T>);

    impl Default for IpaRuntime {
        fn default() -> Self {
            Self::current()
        }
    }

    impl IpaRuntime {
        #[must_use]
        pub fn current() -> Self {
            Self(Handle::current())
        }

        #[must_use]
        pub fn spawn<F>(&self, future: F) -> IpaJoinHandle<F::Output>
        where
            F: Future + Send + 'static,
            F::Output: Send + 'static,
        {
            IpaJoinHandle(self.0.spawn(future))
        }

        /// This is a convenience method to convert a Tokio runtime into
        /// an IPA runtime. It does not assume ownership of the Tokio runtime.
        /// The caller is responsible for ensuring the Tokio runtime is properly
        /// shut down.
        #[must_use]
        pub fn from_tokio_runtime(rt: &Runtime) -> Self {
            Self(rt.handle().clone())
        }
    }

    /// allow using [`IpaRuntime`] as Hyper executor
    #[cfg(feature = "web-app")]
    impl<Fut> hyper::rt::Executor<Fut> for IpaRuntime
    where
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        fn execute(&self, fut: Fut) {
            // Dropping the handle does not terminate the task
            // Clippy wants us to be explicit here.
            drop(self.spawn(fut));
        }
    }

    impl<T> IpaJoinHandle<T> {
        pub fn abort(&self) {
            self.0.abort();
        }
    }

    impl<T: Send + 'static> Future for IpaJoinHandle<T> {
        type Output = T;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            match self.project().0.poll(cx) {
                Poll::Ready(Ok(v)) => Poll::Ready(v),
                Poll::Ready(Err(e)) => match e.try_into_panic() {
                    Ok(p) => std::panic::resume_unwind(p),
                    Err(e) => panic!("Task is cancelled: {e:?}"),
                },
                Poll::Pending => Poll::Pending,
            }
        }
    }
}

#[cfg(feature = "shuttle")]
pub(crate) mod executor {
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    };

    use shuttle_crate::future::{spawn, JoinHandle};

    use crate::shim::Tokio;

    /// Shuttle does not support more than one runtime
    /// so we always use its default
    #[derive(Clone, Default)]
    pub struct IpaRuntime;
    #[pin_project::pin_project]
    pub struct IpaJoinHandle<T>(#[pin] JoinHandle<T>);

    #[cfg(feature = "web-app")]
    impl<Fut> hyper::rt::Executor<Fut> for IpaRuntime
    where
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        fn execute(&self, fut: Fut) {
            drop(self.spawn(fut));
        }
    }

    impl IpaRuntime {
        #[must_use]
        pub fn current() -> Self {
            Self
        }

        #[must_use]
        #[allow(clippy::unused_self)] // to conform with runtime API
        pub fn spawn<F>(&self, future: F) -> IpaJoinHandle<F::Output>
        where
            F: Future + Send + 'static,
            F::Output: Send + 'static,
        {
            IpaJoinHandle(spawn(future))
        }
    }

    impl<T> IpaJoinHandle<T> {
        pub fn abort(&self) {
            self.0.abort();
        }
    }

    impl<T: Send + 'static> Future for IpaJoinHandle<T> {
        type Output = T;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            match self.project().0.poll(cx) {
                Poll::Ready(Ok(v)) => Poll::Ready(v),
                Poll::Ready(Err(e)) => match e.try_into_panic() {
                    Ok(p) => std::panic::resume_unwind(p),
                    Err(e) => panic!("Task is cancelled: {e:?}"),
                },
                Poll::Pending => Poll::Pending,
            }
        }
    }
}

#[cfg(all(feature = "shuttle", test))]
pub(crate) mod test_executor {
    use std::future::Future;

    use shuttle::rand::{rngs::ThreadRng, thread_rng};

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

    pub fn run_random<F, Fut>(f: F)
    where
        F: Fn(ThreadRng) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()>,
    {
        run(move || f(thread_rng()));
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
pub(crate) mod test_executor {
    use std::future::Future;

    use rand::{rngs::StdRng, thread_rng, Rng, SeedableRng};

    // These routines use `FnOnce` because it is easier than dealing with lifetimes of
    // `&mut rng` borrows in futures. If there were a need to support multiple
    // iterations (or to make the API use `Fn` to match the shuttle version), the
    // simplest strategy might be to seed per-iteration RNGs from a primary RNG, like
    // `TestWorld::rng`.
    pub fn run_with<F, Fut, const ITER: usize>(f: F)
    where
        F: FnOnce() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()>,
    {
        tokio::runtime::Builder::new_multi_thread()
            // enable_all() is common to use to build Tokio runtime, but it enables both IO and time drivers.
            // IO driver is not compatible with Miri (https://github.com/rust-lang/miri/issues/2057) which we use to
            // sanitize our tests, so this runtime only enables time driver.
            .enable_time()
            .build()
            .unwrap()
            .block_on(f());
    }

    #[allow(dead_code)]
    pub fn run<F, Fut>(f: F)
    where
        F: FnOnce() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()>,
    {
        run_with::<_, _, 1>(f);
    }

    #[allow(dead_code)]
    pub fn run_with_seed<F, Fut>(seed: u64, f: F)
    where
        F: FnOnce(StdRng) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()>,
    {
        println!("Random seed {seed}");
        let rng = StdRng::seed_from_u64(seed);
        run(move || f(rng));
    }

    #[allow(dead_code)]
    pub fn run_random<F, Fut>(f: F)
    where
        F: FnOnce(StdRng) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()>,
    {
        let seed = thread_rng().gen();
        run_with_seed(seed, f);
    }
}

pub const CRATE_NAME: &str = env!("CARGO_CRATE_NAME");

/// This macro should be called in a binary that uses `ipa_core`, if that binary wishes
/// to use jemalloc.
///
/// Besides declaring the `#[global_allocator]`, the macro also activates some memory
/// reporting.
#[macro_export]
macro_rules! use_jemalloc {
    () => {
        #[global_allocator]
        static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

        $crate::telemetry::memory::jemalloc::activate();
    };
}

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
#[cfg(not(any(compact_gate, descriptive_gate)))]
compile_error!("At least one of `compact_gate` or `descriptive_gate` features must be enabled");

#[cfg(test)]
mod tests {
    /// Tests in this module ensure both Shuttle and Tokio runtimes conform to the same API
    mod executor {
        use crate::{executor::IpaRuntime, test_executor::run};

        #[test]
        #[should_panic(expected = "task panicked")]
        fn handle_join_panicked() {
            run(|| async move {
                let rt = IpaRuntime::current();
                rt.spawn(async { panic!("task panicked") }).await;
            });
        }

        #[test]
        /// It is nearly impossible to intentionally hang a Shuttle task. Its executor
        /// detects that immediately and panics with a deadlock error. We only want to test
        /// the API, so it is not that important to panic with cancellation error
        #[cfg_attr(not(feature = "shuttle"), should_panic(expected = "Task is cancelled"))]
        fn handle_abort() {
            run(|| async move {
                let rt = IpaRuntime::current();
                let handle = rt.spawn(async {
                    #[cfg(not(feature = "shuttle"))]
                    futures::future::pending::<()>().await;
                });

                handle.abort();
                handle.await;
            });
        }
    }
}
