use std::{
    cell::RefCell,
    mem,
};
use crossbeam_channel::{Receiver, Sender};
use crate::{context::CurrentThreadContext, MetricsStore};

thread_local! {
    /// Collector that is installed in a thread. It is responsible for receiving metrics from
    /// all threads and aggregating them.
    static COLLECTOR: RefCell<Option<MetricsCollector>> = const { RefCell::new(None) }
}

fn installer() -> (MetricsCollector, MetricsProducer) {
    let (tx, rx) = crossbeam_channel::unbounded();
    (
        MetricsCollector {
            rx,
            local_store: MetricsStore::default(),
        },
        MetricsProducer { tx },
    )
}

#[derive(Clone)]
struct MetricsProducer {
    tx: Sender<MetricsStore>,
}

impl MetricsProducer {
    pub fn install(&self) {
        CurrentThreadContext::init(self.tx.clone());
    }

    /// Returns a drop handle that should be used when thread is stopped.
    /// In an ideal world, a destructor on [`MetricsContext`] could do this,
    /// but as pointed in [`LocalKey`] documentation, deadlocks are possible
    /// if another TLS storage is accessed at destruction time.
    ///
    /// I actually ran into this problem with crossbeam channels. Send operation
    /// requires access to `thread::current` and that panics at runtime if called
    /// from inside `Drop`.
    ///
    /// [`LocalKey`]: <https://doc.rust-lang.org/std/thread/struct.LocalKey.html#platform-specific-behavior>
    pub fn drop_handle(&self) -> ProducerDropHandle {
        ProducerDropHandle
    }
}

#[must_use]
struct ProducerDropHandle;

impl Drop for ProducerDropHandle {
    fn drop(&mut self) {
        CurrentThreadContext::flush()
    }
}

struct MetricsCollector {
    rx: Receiver<MetricsStore>,
    local_store: MetricsStore,
}

impl MetricsCollector {
    pub fn install(self) {
        COLLECTOR.with(|c| {
            assert!(
                c.borrow_mut().replace(self).is_none(),
                "Already initialized"
            );
        });
    }

    pub fn recv_all(&mut self) {
        loop {
            match self.rx.recv() {
                Ok(m) => self.local_store.merge(m),
                Err(_) => break,
            }
        }
    }

    pub fn wait_for_all() -> MetricsStore {
        COLLECTOR.with(|c| {
            let mut c = c.borrow_mut();
            let collector = c.as_mut().expect("Collector is installed");
            collector.recv_all();

            mem::take(&mut collector.local_store)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        thread,
        thread::{Scope, ScopedJoinHandle},
    };

    use crate::{
        collector::{installer, MetricsCollector, MetricsProducer},
        counter, metric_name,
    };

    struct MeteredScope<'scope, 'env: 'scope>(&'scope Scope<'scope, 'env>, MetricsProducer);

    impl<'scope, 'env: 'scope> MeteredScope<'scope, 'env> {
        fn spawn<F, T>(&self, f: F) -> ScopedJoinHandle<'scope, T>
        where
            F: FnOnce() -> T + Send + 'scope,
            T: Send + 'scope,
        {
            let producer = self.1.clone();

            self.0.spawn(move || {
                producer.install();
                let r = f();
                let _ = producer.drop_handle();

                r
            })
        }
    }

    trait IntoMetered<'scope, 'env: 'scope> {
        fn metered(&'scope self, meter: MetricsProducer) -> MeteredScope<'scope, 'env>;
    }

    impl<'scope, 'env: 'scope> IntoMetered<'scope, 'env> for Scope<'scope, 'env> {
        fn metered(&'scope self, meter: MetricsProducer) -> MeteredScope<'scope, 'env> {
            MeteredScope(self, meter)
        }
    }

    #[test]
    fn start_stop() {
        let (collector, producer) = installer();
        let handle = thread::spawn(|| {
            collector.install();
            MetricsCollector::wait_for_all().counter_value(&metric_name!("foo"))
        });

        thread::scope(move |s| {
            let s = s.metered(producer);
            s.spawn(|| counter!("foo", 3));
            s.spawn(|| counter!("foo", 5));
        });

        assert_eq!(8, handle.join().unwrap());
    }
}
