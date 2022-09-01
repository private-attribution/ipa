use crate::error::BoxError;
use crate::helpers::Identity;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("used self as peer")]
    SelfAsPeer,
    #[error("invalid peer: {0}")]
    InvalidPeer(Identity),
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
    #[error(transparent)]
    Hyper(#[from] hyper::Error),
    #[error("json parse error: {0}")]
    JsonParse(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
