use std::fmt::Debug;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("already exists")]
    AlreadyExists,
    #[error("already setup")]
    AlreadySetup,
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

    #[error("failed to decode hex: {0}")]
    #[cfg(feature = "cli")]
    Hex(#[from] hex::FromHexError),
    #[error("problem during IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse json: {0}")]
    #[cfg(feature = "enable-serde")]
    Serde(#[from] serde_json::Error),
}

#[allow(clippy::module_name_repetitions)]
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub type Res<T> = Result<T, Error>;
