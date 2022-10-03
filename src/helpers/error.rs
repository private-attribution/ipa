use crate::error::BoxError;
use crate::helpers::Identity;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("An error occurred while sending data to {dest:?}")]
    SendError {
        dest: Identity,

        #[source]
        inner: BoxError,
    },
    #[error("An error occurred while receiving data from {source:?}")]
    ReceiveError {
        source: Identity,
        #[source]
        inner: BoxError,
    },
}

impl Error {
    pub fn send_error<E: std::error::Error + Send + Sync + 'static>(dest: Identity, inner: E) -> Error {
        Self::SendError { dest, inner: Box::new(inner) }
    }
}

pub type Result<T> = std::result::Result<T, Error>;