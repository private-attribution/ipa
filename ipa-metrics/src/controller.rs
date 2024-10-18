use crossbeam_channel::Sender;

use crate::MetricsStore;

/// Indicates the current status of collector thread
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Status {
    /// There are at least one active thread that can send
    /// the store snapshots to the collector. Collector is actively
    /// listening for new snapshots.
    Active,
    /// All threads have been disconnected from this collector,
    /// and it is currently awaiting shutdown via [`Command::Stop`]
    Disconnected,
}

pub enum Command {
    Snapshot(Sender<MetricsStore>),
    Stop(Sender<()>),
    Status(Sender<Status>),
}

/// Handle to communicate with centralized metrics collection system.
pub struct Controller {
    pub(super) tx: Sender<Command>,
}

impl Controller {
    /// Request new metric snapshot from the collector thread.
    /// Blocks current thread until the snapshot is received
    ///
    /// ## Errors
    /// If collector thread is disconnected or an error occurs during snapshot request
    ///
    /// ## Example
    /// ```rust
    /// use ipa_metrics::{install_new_thread, MetricsStore};
    ///
    /// let (_, controller, _handle) = install_new_thread().unwrap();
    /// let snapshot = controller.snapshot().unwrap();
    /// println!("Current metrics: {snapshot:?}");
    /// ```
    #[inline]
    pub fn snapshot(&self) -> Result<MetricsStore, String> {
        let (tx, rx) = crossbeam_channel::bounded(0);
        self.tx
            .send(Command::Snapshot(tx))
            .map_err(|e| format!("An error occurred while requesting metrics snapshot: {e}"))?;
        rx.recv().map_err(|e| format!("Disconnected channel: {e}"))
    }

    /// Send request to terminate the collector thread.
    /// Blocks current thread until the snapshot is received.
    /// If this request is successful, any subsequent snapshot
    /// or stop requests will return an error.
    ///
    /// ## Errors
    /// If collector thread is disconnected or an error occurs while sending
    /// or receiving data from the collector thread.
    ///
    /// ## Example
    /// ```rust
    /// use ipa_metrics::{install_new_thread, MetricsStore};
    ///
    /// let (_, controller, _handle) = install_new_thread().unwrap();
    /// controller.stop().unwrap();
    /// ```
    pub fn stop(self) -> Result<(), String> {
        let (tx, rx) = crossbeam_channel::bounded(0);
        self.tx
            .send(Command::Stop(tx))
            .map_err(|e| format!("An error occurred while requesting termination: {e}"))?;
        rx.recv().map_err(|e| format!("Disconnected channel: {e}"))
    }

    /// Request current collector status.
    ///
    /// ## Errors
    /// If collector thread is disconnected or an error occurs while sending
    /// or receiving data from the collector thread.
    ///
    /// ## Example
    /// ```rust
    /// use ipa_metrics::{install_new_thread, ControllerStatus};
    ///
    /// let (_, controller, _handle) = install_new_thread().unwrap();
    /// let status = controller.status().unwrap();
    /// println!("Collector status: {status:?}");
    /// ```
    #[inline]
    pub fn status(&self) -> Result<Status, String> {
        let (tx, rx) = crossbeam_channel::bounded(0);
        self.tx
            .send(Command::Status(tx))
            .map_err(|e| format!("An error occurred while requesting status: {e}"))?;
        rx.recv().map_err(|e| format!("Disconnected channel: {e}"))
    }
}
