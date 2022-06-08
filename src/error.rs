use std::fmt::Debug;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("already exists")]
    AlreadyExists,
    #[error("internal")]
    Internal,
    #[error("invalid id")]
    InvalidId,
    #[error("invalid role")]
    InvalidRole,
    #[error("not enough helpers")]
    NotEnoughHelpers,
    #[error("not found")]
    NotFound,
    #[error("problem during redis operation: {0}")]
    RedisError(#[from] redis::RedisError),
    #[error("too many helpers")]
    TooManyHelpers,
    #[error("thread died: {0}")]
    DeadThread(#[from] std::sync::mpsc::SendError<crate::net::Message>),
    #[error("thread failed: {0}")]
    TaskFailed(#[from] tokio::task::JoinError),

    #[error("failed to decode hex: {0}")]
    #[cfg(feature = "cli")]
    Hex(#[from] hex::FromHexError),
    #[error("problem during IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse json: {0}")]
    #[cfg(feature = "enable-serde")]
    Serde(#[from] serde_json::Error),

    // module errors
    #[error("pipeline error: {0}")]
    Pipeline(#[from] crate::pipeline::error::Error),
}

pub type Result<T> = core::result::Result<T, Error>;
