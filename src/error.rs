use std::{backtrace::Backtrace, fmt::Debug};

use thiserror::Error;

use crate::{report::InvalidReportError, task::JoinError};

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
    #[error("invalid report: {0}")]
    InvalidReport(#[from] InvalidReportError),
    #[error("unsupported: {0}")]
    Unsupported(String),
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

/// Set up a global panic hook that dumps the panic information to our tracing subsystem if it is
/// available and duplicates that to standard error output.
///
/// Note that it is not possible to reliably test panic hooks because Rust test runner uses more
/// than one thread by default.
///
/// ## Panics
/// If caller thread is panicking while calling this function.
pub fn set_global_panic_hook() {
    let default_hook = std::panic::take_hook();

    std::panic::set_hook(Box::new(move |panic_info| {
        let backtrace = Backtrace::force_capture();

        let cur_thread = std::thread::current();
        tracing::error!(
            "{thread_id:?} \"{thread_name}\" {panic_info}\nstack trace:\n{backtrace}",
            thread_id = cur_thread.id(),
            thread_name = cur_thread.name().unwrap_or("<no_name>")
        );
        (default_hook)(panic_info);
    }));
}
