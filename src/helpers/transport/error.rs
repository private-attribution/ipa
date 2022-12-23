use crate::error::BoxError;
use crate::helpers::TransportCommand;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to send {command:?}: {inner:?}")]
    SendFailed {
        command: TransportCommand,
        #[source]
        inner: BoxError,
    },
}

#[cfg(any(test, feature = "test-fixture"))]
impl From<tokio::sync::mpsc::error::SendError<TransportCommand>> for Error {
    fn from(value: tokio::sync::mpsc::error::SendError<TransportCommand>) -> Self {
        Self::SendFailed {
            command: value.0,
            inner: "channel closed".into(),
        }
    }
}
