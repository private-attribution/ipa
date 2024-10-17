use std::cell::RefCell;

use crossbeam_channel::{Receiver, Select};

use crate::{ControllerCommand, MetricsStore};

thread_local! {
    /// Collector that is installed in a thread. It is responsible for receiving metrics from
    /// all threads and aggregating them.
    static COLLECTOR: RefCell<Option<MetricsCollector>> = const { RefCell::new(None) }
}

pub struct Installed;

impl Installed {
    pub fn block_until_shutdown(&self) -> MetricsStore {
        MetricsCollector::with_current_mut(|c| {
            c.event_loop();

            std::mem::take(&mut c.local_store)
        })
    }
}

pub struct MetricsCollector {
    pub(super) rx: Receiver<MetricsStore>,
    pub(super) local_store: MetricsStore,
    pub(super) command_rx: Receiver<ControllerCommand>,
}

impl MetricsCollector {
    pub fn install(self) -> Installed {
        COLLECTOR.with_borrow_mut(|c| {
            assert!(c.replace(self).is_none(), "Already initialized");
        });

        Installed
    }

    fn event_loop(&mut self) {
        let mut select = Select::new();
        let data_idx = select.recv(&self.rx);
        let command_idx = select.recv(&self.command_rx);

        loop {
            let next_op = select.select();
            match next_op.index() {
                i if i == data_idx => match next_op.recv(&self.rx) {
                    Ok(store) => {
                        tracing::trace!("Collector received more data: {store:?}");
                        println!("Collector received more data: {store:?}");
                        self.local_store.merge(store)
                    }
                    Err(e) => {
                        tracing::debug!("No more threads collecting metrics. Disconnected: {e}");
                        select.remove(data_idx);
                    }
                },
                i if i == command_idx => match next_op.recv(&self.command_rx) {
                    Ok(ControllerCommand::Snapshot(tx)) => {
                        tracing::trace!("Snapshot request received");
                        println!("snapshot request received");
                        tx.send(self.local_store.clone()).unwrap();
                    }
                    Ok(ControllerCommand::Stop(tx)) => {
                        tx.send(()).unwrap();
                        break;
                    }
                    Err(e) => {
                        tracing::debug!("Metric controller is disconnected: {e}");
                        break;
                    }
                },
                _ => unreachable!(),
            }
        }
    }

    pub fn with_current_mut<F: FnOnce(&mut Self) -> T, T>(f: F) -> T {
        COLLECTOR.with_borrow_mut(|c| {
            let collector = c.as_mut().expect("Collector is installed");
            f(collector)
        })
    }
}

impl Drop for MetricsCollector {
    fn drop(&mut self) {
        tracing::debug!("Collector is dropped");
    }
}

#[cfg(test)]
mod tests {
    use std::{
        thread,
        thread::{Scope, ScopedJoinHandle},
    };

    use crate::{counter, installer, producer::Producer, thread_installer};

    struct MeteredScope<'scope, 'env: 'scope>(&'scope Scope<'scope, 'env>, Producer);

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
        fn metered(&'scope self, meter: Producer) -> MeteredScope<'scope, 'env>;
    }

    impl<'scope, 'env: 'scope> IntoMetered<'scope, 'env> for Scope<'scope, 'env> {
        fn metered(&'scope self, meter: Producer) -> MeteredScope<'scope, 'env> {
            MeteredScope(self, meter)
        }
    }

    #[test]
    fn start_stop() {
        let (collector, producer, controller) = installer();
        let handle = thread::spawn(|| {
            let store = collector.install().block_until_shutdown();
            store.counter_val(counter!("foo"))
        });

        thread::scope(move |s| {
            let s = s.metered(producer);
            s.spawn(|| counter!("foo", 3)).join().unwrap();
            s.spawn(|| counter!("foo", 5)).join().unwrap();
            controller.stop().unwrap();
        });

        assert_eq!(8, handle.join().unwrap())
    }

    #[test]
    fn with_thread() {
        let (producer, controller, handle) = thread_installer().unwrap();
        thread::scope(move |s| {
            let s = s.metered(producer);
            s.spawn(|| counter!("baz", 4));
            s.spawn(|| counter!("bar", 1));
            s.spawn(|| controller.stop().unwrap());
        });

        handle.join().unwrap() // Collector thread should be terminated by now
    }
}
