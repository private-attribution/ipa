use crossbeam_channel::Sender;

use crate::MetricsStore;

pub enum Command {
    Snapshot(Sender<MetricsStore>),
    Stop(Sender<()>),
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
}
