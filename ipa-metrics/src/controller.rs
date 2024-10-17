use crossbeam_channel::Sender;

use crate::MetricsStore;

pub enum Command {
    Snapshot(Sender<MetricsStore>),
    Stop(Sender<()>),
}

pub struct Controller {
    pub(super) tx: Sender<Command>,
}

impl Controller {
    pub fn snapshot(&self) -> Result<MetricsStore, String> {
        let (tx, rx) = crossbeam_channel::bounded(0);
        self.tx
            .send(Command::Snapshot(tx))
            .map_err(|e| format!("An error occurred while requesting metrics snapshot: {e}"))?;
        rx.recv().map_err(|e| format!("Disconnected channel: {e}"))
    }

    pub fn stop(self) -> Result<(), String> {
        let (tx, rx) = crossbeam_channel::bounded(0);
        self.tx
            .send(Command::Stop(tx))
            .map_err(|e| format!("An error occurred while requesting metrics snapshot: {e}"))?;
        rx.recv().map_err(|e| format!("Disconnected channel: {e}"))
    }
}
