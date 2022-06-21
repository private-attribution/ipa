use std::fmt::Debug;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to handle serde message: {0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("failed to parse message: {0}")]
    ParseError(#[from] std::str::Utf8Error),
    #[error("problem communicating between threads: {0}")]
    ThreadError(Box<dyn std::error::Error + Send + Sync>),
}

impl<T: Debug + Send + Sync + 'static> From<tokio::sync::mpsc::error::SendError<T>> for Error {
    fn from(e: tokio::sync::mpsc::error::SendError<T>) -> Self {
        Error::ThreadError(e.into())
    }
}
impl From<tokio::sync::oneshot::error::RecvError> for Error {
    fn from(e: tokio::sync::oneshot::error::RecvError) -> Self {
        Error::ThreadError(e.into())
    }
}
impl From<tokio::task::JoinError> for Error {
    fn from(e: tokio::task::JoinError) -> Self {
        Error::ThreadError(e.into())
    }
}

pub type Result<T> = core::result::Result<T, Error>;
