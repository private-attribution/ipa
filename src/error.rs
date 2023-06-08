use crate::task::JoinError;
use std::fmt::Debug;
use thiserror::Error;

/// An error raised by the IPA protocol.
///
/// This error type could be thought of as `ipa::protocol::Error`. There are other error types for
/// some of the other modules:
///  * `ipa::helpers::Error`, for infrastructure
///  * `ipa::ff::Error`, for finite field routines
///  * `ipa::net::Error`, for the HTTP transport
///  * `ipa::app::Error`, for the report collector query APIs
#[derive(Error, Debug)]
pub enum Error {
    #[error("already exists")]
    AlreadyExists,
    #[error("already setup")]
    AlreadySetup,
    #[error("internal")]
    Internal,
    #[error("invalid id found: {0}")]
    InvalidId(String),
    #[error("invalid role")]
    InvalidRole,
    #[error("not enough helpers")]
    NotEnoughHelpers,
    #[error("not found")]
    NotFound,
    #[error("too many helpers")]
    TooManyHelpers,
    #[error("failed to parse: {0}")]
    ParseError(BoxError),
    #[error("malicious security check failed")]
    MaliciousSecurityCheckFailed,
    #[error("malicious reveal failed")]
    MaliciousRevealFailed,
    #[error("problem during IO: {0}")]
    Io(#[from] std::io::Error),
    // TODO remove if this https://github.com/awslabs/shuttle/pull/109 gets approved
    #[cfg(not(feature = "shuttle"))]
    #[error("runtime error")]
    RuntimeError(#[from] JoinError),
    #[cfg(feature = "shuttle")]
    #[error("runtime error")]
    RuntimeError(JoinError),
    #[error("failed to parse json: {0}")]
    #[cfg(feature = "enable-serde")]
    Serde(#[from] serde_json::Error),
    #[error("Infrastructure error: {0}")]
    InfraError(#[from] crate::helpers::Error),
    #[error("Value truncation error: {0}")]
    FieldValueTruncation(String),
    #[error("Invalid query parameter: {0}")]
    InvalidQueryParameter(String),
}

impl Default for Error {
    fn default() -> Self {
        Self::Internal
    }
}

impl Error {
    #[must_use]
    pub fn path_parse_error(source: &str) -> Error {
        Error::ParseError(format!("unexpected value \"{source}\" in path").into())
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(err: std::num::ParseIntError) -> Self {
        Error::ParseError(err.into())
    }
}

pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub type Res<T> = Result<T, Error>;
