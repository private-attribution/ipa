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
