use std::{cell::RefCell, mem};

use crossbeam_channel::Sender;

use crate::MetricsStore;

thread_local! {
    pub(crate) static METRICS_CTX: RefCell<MetricsContext> = const { RefCell::new(MetricsContext::new()) }
}

#[macro_export]
macro_rules! counter {
    ($metric:expr, $val:expr $(, $l:expr => $v:expr)*) => {{
        let name = $crate::metric_name!($metric $(, $l => $v)*);
        $crate::MetricsCurrentThreadContext::store_mut(|store| store.counter(&name).inc($val))
    }};
    ($metric:expr $(, $l:expr => $v:expr)*) => {{
        $crate::metric_name!($metric $(, $l => $v)*)
    }};
}

/// Provides access to the metric store associated with the current thread.
/// If there is no store associated with the current thread, it will create a new one.
pub struct CurrentThreadContext;

impl CurrentThreadContext {
    pub fn init(tx: Sender<MetricsStore>) {
        METRICS_CTX.with_borrow_mut(|ctx| ctx.init(tx));
    }

    pub fn flush() {
        METRICS_CTX.with_borrow_mut(|ctx| ctx.flush());
    }

    pub fn is_connected() -> bool {
        METRICS_CTX.with_borrow(|ctx| ctx.is_connected())
    }

    pub fn store<F: FnOnce(&MetricsStore) -> T, T>(f: F) -> T {
        METRICS_CTX.with_borrow(|ctx| f(ctx.store()))
    }

    pub fn store_mut<F: FnOnce(&mut MetricsStore) -> T, T>(f: F) -> T {
        METRICS_CTX.with_borrow_mut(|ctx| f(ctx.store_mut()))
    }
}

/// This context is used inside thread-local storage,
/// so it must be wrapped inside [`std::cell::RefCell`].
///
/// For single-threaded applications, it is possible
/// to use it w/o connecting to the collector thread.
pub struct MetricsContext {
    store: MetricsStore,
    /// Handle to send metrics to the collector thread
    tx: Option<Sender<MetricsStore>>,
}

impl Default for MetricsContext {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsContext {
    pub const fn new() -> Self {
        Self {
            store: MetricsStore::new(),
            tx: None,
        }
    }

    /// Connects this context to the collector thread.
    /// Sender will be used to send data from this thread
    fn init(&mut self, tx: Sender<MetricsStore>) {
        assert!(self.tx.is_none(), "Already connected");

        self.tx = Some(tx);
    }

    pub fn store(&self) -> &MetricsStore {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut MetricsStore {
        &mut self.store
    }

    fn is_connected(&self) -> bool {
        self.tx.is_some()
    }

    fn flush(&mut self) {
        if self.is_connected() {
            let store = mem::take(&mut self.store);
            match self.tx.as_ref().unwrap().send(store) {
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("MetricsContext is not connected: {e}");
                }
            }
        } else {
            tracing::warn!("MetricsContext is not connected");
        }
    }
}

impl Drop for MetricsContext {
    fn drop(&mut self) {
        if !self.store.is_empty() {
            tracing::warn!(
                "Non-empty metric store is dropped: {} metrics lost",
                self.store.len()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::MetricsContext;

    /// Each thread has its local store by default, and it is exclusive to it
    #[test]
    #[cfg(feature = "partitions")]
    fn local_store() {
        use crate::context::CurrentThreadContext;

        crate::set_partition(0xdeadbeef);
        counter!("foo", 7);

        std::thread::spawn(|| {
            counter!("foo", 1);
            counter!("foo", 5);
            assert_eq!(
                5,
                CurrentThreadContext::store(|store| store.counter_value(&counter!("foo")))
            );
        });

        assert_eq!(
            7,
            CurrentThreadContext::store(|store| store.counter_value(&counter!("foo")))
        );
    }

    #[test]
    fn default() {
        assert_eq!(0, MetricsContext::default().store().len())
    }
}
