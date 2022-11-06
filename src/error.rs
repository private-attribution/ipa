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
    #[error("failed to decode hex: {0}")]
    #[cfg(feature = "cli")]
    Hex(#[from] hex::FromHexError),
    #[error("problem during IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse json: {0}")]
    #[cfg(feature = "enable-serde")]
    Serde(#[from] serde_json::Error),
    #[error("Infrastructure error: {0}")]
    InfraError(#[from] crate::helpers::Error),
}

impl Error {
    #[must_use]
    #[allow(clippy::module_name_repetitions)] // follows convention of `Error::ParseError`
    pub fn path_parse_error(source: &str) -> Error {
        Error::ParseError(format!("unexpected value \"{source}\" in path").into())
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(err: std::num::ParseIntError) -> Self {
        Error::ParseError(err.into())
    }
}

#[allow(clippy::module_name_repetitions)]
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub type Res<T> = Result<T, Error>;
