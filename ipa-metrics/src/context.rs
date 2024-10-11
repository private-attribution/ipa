use std::{cell::RefCell, mem};

use crossbeam_channel::Sender;

use crate::MetricsStore;

thread_local! {
    pub(crate) static METRICS_CTX: RefCell<MetricsContext> = const { RefCell::new(MetricsContext::new()) }
}

#[macro_export]
macro_rules! counter {
    // Match when two key-value pairs are provided
    ($metric:expr, $val:expr, $l1:expr => $v1:expr, $l2:expr => $v2:expr$(,)?) => {{
        let name = $crate::metric_name!($metric, $l1 => $v1, $l2 => $v2);
        $crate::MetricsContext::current_thread(|ctx| ctx.store_mut().counter(&name).inc($val))
    }};
    // Match when one key-value pair is provided
    ($metric:expr, $val:expr, $l1:expr => $v1:expr) => {{
        let name = $crate::metric_name!($metric, $l1 => $v1);
        $crate::MetricsContext::current_thread(|ctx| ctx.store_mut().counter(&name).inc($val))
    }};
    // Match when no key-value pairs are provided
    ($metric:expr, $val:expr) => {{
        let name = $crate::metric_name!($metric);
        $crate::MetricsContext::current_thread(|ctx| ctx.store_mut().counter(&name).inc($val))
    }};
}

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

impl MetricsContext {
    pub const fn new() -> Self {
        Self {
            store: MetricsStore::new(),
            tx: None,
        }
    }

    pub fn current_thread<F: FnOnce(&mut MetricsContext) -> T, T>(f: F) -> T {
        METRICS_CTX.with_borrow_mut(f)
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

    #[cfg(not(feature = "partitions"))]
    pub fn store_mut(&mut self) -> &mut MetricsStore {
        &mut self.store
    }

    #[cfg(feature = "partitions")]
    pub fn store_mut(&mut self) -> &mut crate::store::Store {
        self.store.current_mut()
    }

    fn is_connected(&self) -> bool {
        self.tx.is_some()
    }

    fn flush(&mut self) {
        if self.is_connected() {
            let store = mem::take(&mut self.store);
            match self.tx.as_ref().unwrap().send(store) {
                Ok(_) => {}
                Err(_) => {
                    // TODO: tracing
                    eprintln!("Failed to send metrics: disconnected");
                }
            }
        } else {
            eprintln!("MetricsContext is not connected to the collector thread");
        }
    }
}

impl Drop for MetricsContext {
    fn drop(&mut self) {
        if !self.store.is_empty() {
            eprintln!("Metrics store is not empty, but dropped");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{mem, thread};

    use crate::{
        context::METRICS_CTX, kind::CounterValue, metric_name, set_test_partition, MetricName,
    };

    fn get_counter_value(name: &MetricName) -> CounterValue {
        let v = METRICS_CTX.with_borrow(|ctx| ctx.store().counter_value(name));
        // empty the store to avoid warnings about non-empty store being dropped
        METRICS_CTX.with_borrow_mut(|ctx| mem::take(ctx.store_mut()));

        v
    }

    /// Each thread has its local store by default, and it is exclusive to it
    #[test]
    fn local_store() {
        set_test_partition();
        counter!("foo", 7);

        thread::spawn(|| {
            counter!("foo", 5);
            assert_eq!(5, get_counter_value(&metric_name!("foo")));
        });

        assert_eq!(7, get_counter_value(&metric_name!("foo")));
    }
}
