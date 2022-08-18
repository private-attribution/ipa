use crate::net::MpcServerError;
use axum::response::{IntoResponse, Response};
use thiserror::Error;
pub mod step;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid step")]
    StepParseError,
}

impl From<Error> for MpcServerError {
    fn from(err: Error) -> Self {
        match err {
            Error::StepParseError => MpcServerError::BadPathString(),
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        MpcServerError::from(self).into_response()
    }
}
