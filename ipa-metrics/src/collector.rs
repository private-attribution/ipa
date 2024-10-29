use std::cell::RefCell;

use crossbeam_channel::{Receiver, Select};

use crate::{
    controller::{Command, Status},
    ControllerCommand, MetricsStore,
};

thread_local! {
    /// Collector that is installed in a thread. It is responsible for receiving metrics from
    /// all threads and aggregating them.
    static COLLECTOR: RefCell<Option<MetricsCollector>> = const { RefCell::new(None) }
}

/// Convenience struct to block the current thread on metric collection
pub struct Installed;

impl Installed {
    #[allow(clippy::unused_self)]
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
    /// This installs metrics collection mechanism to current thread.
    ///
    /// ## Panics
    /// It panics if there is another collector system already installed.
    #[allow(clippy::must_use_candidate)]
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
        let mut state = Status::Active;

        loop {
            let next_op = select.select();
            match next_op.index() {
                i if i == data_idx => match next_op.recv(&self.rx) {
                    Ok(store) => {
                        tracing::trace!("Collector received more data: {store:?}");
                        self.local_store.merge(store);
                    }
                    Err(e) => {
                        tracing::debug!("No more threads collecting metrics. Disconnected: {e}");
                        select.remove(data_idx);
                        state = Status::Disconnected;
                    }
                },
                i if i == command_idx => match next_op.recv(&self.command_rx) {
                    Ok(ControllerCommand::Snapshot(tx)) => {
                        tracing::trace!("Snapshot request received");
                        tx.send(self.local_store.clone()).unwrap();
                    }
                    Ok(ControllerCommand::Stop(tx)) => {
                        tracing::trace!("Stop signal received");
                        tx.send(()).unwrap();
                        break;
                    }
                    Ok(Command::Status(tx)) => {
                        tx.send(state).unwrap();
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

    fn with_current_mut<F: FnOnce(&mut Self) -> T, T>(f: F) -> T {
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

    use crate::{
        controller::Status, counter, install, install_new_thread, producer::Producer,
        MetricChannelType,
    };

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
        let (collector, producer, controller) = install(MetricChannelType::Unbounded);
        let handle = thread::spawn(|| {
            let store = collector.install().block_until_shutdown();
            store.counter_val(counter!("foo"))
        });

        thread::scope(move |s| {
            let s = s.metered(producer);
            s.spawn(|| counter!("foo", 3)).join().unwrap();
            s.spawn(|| counter!("foo", 5)).join().unwrap();
            drop(s); // this causes collector to eventually stop receiving signals
            while controller.status().unwrap() == Status::Active {}
            controller.stop().unwrap();
        });

        assert_eq!(8, handle.join().unwrap());
    }

    #[test]
    fn with_thread() {
        let (producer, controller, handle) =
            install_new_thread(MetricChannelType::Unbounded).unwrap();
        thread::scope(move |s| {
            let s = s.metered(producer);
            s.spawn(|| counter!("baz", 4));
            s.spawn(|| counter!("bar", 1));
            s.spawn(|| {
                let snapshot = controller.snapshot().unwrap();
                println!("snapshot: {snapshot:?}");
                controller.stop().unwrap();
            });
        });

        handle.join().unwrap(); // Collector thread should be terminated by now
    }

    #[test]
    fn with_thread_rendezvous() {
        let (producer, controller, _handle) =
            install_new_thread(MetricChannelType::Rendezvous).unwrap();
        let counter = thread::scope(move |s| {
            let s = s.metered(producer);
            s.spawn(|| counter!("foo", 3)).join().unwrap();
            s.spawn(|| counter!("foo", 5)).join().unwrap();
            // we don't need to check the status because producer threads are now
            // blocked until the collector receives their stores. This means that
            // the snapshot must be up to date by now.
            controller.snapshot().unwrap().counter_val(counter!("foo"))
        });

        assert_eq!(8, counter);
    }
}
