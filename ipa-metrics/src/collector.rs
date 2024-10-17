use std::{cell::RefCell, mem};

use crossbeam_channel::{Receiver, Sender};

use crate::{context::CurrentThreadContext, MetricsStore};

thread_local! {
    /// Collector that is installed in a thread. It is responsible for receiving metrics from
    /// all threads and aggregating them.
    static COLLECTOR: RefCell<Option<MetricsCollector>> = const { RefCell::new(None) }
}

pub fn installer() -> (
    MetricsCollector,
    MetricsProducer,
    MetricsCollectorController,
) {
    let (command_tx, command_rx) = crossbeam_channel::unbounded();
    let (tx, rx) = crossbeam_channel::unbounded();
    (
        MetricsCollector {
            rx,
            local_store: MetricsStore::default(),
            command_rx,
        },
        MetricsProducer { tx },
        MetricsCollectorController { tx: command_tx },
    )
}

#[derive(Clone)]
pub struct MetricsProducer {
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
pub struct ProducerDropHandle;

impl Drop for ProducerDropHandle {
    fn drop(&mut self) {
        CurrentThreadContext::flush()
    }
}

pub enum Command {
    Snapshot(Sender<MetricsStore>),
}

pub struct MetricsCollectorController {
    tx: Sender<Command>,
}

impl MetricsCollectorController {
    pub fn snapshot(&self) -> Result<MetricsStore, String> {
        let (tx, rx) = crossbeam_channel::bounded(0);
        self.tx
            .send(Command::Snapshot(tx))
            .map_err(|e| format!("An error occurred while requesting metrics snapshot: {e}"))?;
        rx.recv().map_err(|e| format!("Disconnected channel: {e}"))
    }
}

pub struct MetricsCollector {
    rx: Receiver<MetricsStore>,
    local_store: MetricsStore,
    command_rx: Receiver<Command>,
}

impl MetricsCollector {
    pub fn install(self) {
        COLLECTOR.with_borrow_mut(|c| {
            assert!(c.replace(self).is_none(), "Already initialized");
        });
    }

    fn event_loop(&mut self) {
        loop {
            crossbeam_channel::select! {
                recv(self.rx) -> msg => {
                    self.local_store.merge(msg.unwrap());
                }
                recv(self.command_rx) -> cmd => {
                    match cmd {
                        Ok(Command::Snapshot(tx)) => {
                            tx.send(self.local_store.clone()).unwrap();
                        }
                        Err(_) => {
                            eprintln!("disconnected");
                            break;
                        }
                    }
                }
            }
        }
    }

    pub fn with_current_mut<F: FnOnce(&mut Self) -> T, T>(f: F) -> T {
        COLLECTOR.with_borrow_mut(|c| {
            let collector = c.as_mut().expect("Collector is installed");
            f(collector)
        })
    }

    pub fn try_recv_one(&mut self) -> &MetricsStore {
        if let Ok(store) = self.rx.try_recv() {
            self.local_store.merge(store)
        }
        &self.local_store
    }

    pub fn recv_one(&mut self) -> &MetricsStore {
        if let Ok(store) = self.rx.recv() {
            self.local_store.merge(store)
        }
        &self.local_store
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
        COLLECTOR.with_borrow_mut(|c| {
            let collector = c.as_mut().expect("Collector is installed");
            collector.recv_all();

            mem::take(&mut collector.local_store)
        })
    }

    pub fn wait_for_shutdown() {
        COLLECTOR.with_borrow_mut(|c| {
            let collector = c.as_mut().expect("Collector is installed");
            collector.event_loop();
        });
    }

}

impl Drop for MetricsCollector {
    fn drop(&mut self) {
        eprintln!("collector dropped");
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
        counter, metric_name, set_test_partition,
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
        let (collector, producer, _) = installer();
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
