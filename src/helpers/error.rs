use crate::error::BoxError;
use crate::helpers::ring::HelperAddr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("An error occurred while sending data to {dest:?}")]
    SendError {
        dest: HelperAddr,

        #[source]
        inner: BoxError,
    },
    #[error("An error occurred while receiving data from {source:?}")]
    ReceiveError {
        source: HelperAddr,
        #[source]
        inner: BoxError,
    },
}
