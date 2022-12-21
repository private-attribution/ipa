use crate::error::BoxError;
use crate::protocol::QueryId;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tokio::sync::mpsc;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    BadQueryString(#[source] BoxError),
    #[error("header not found: {0}")]
    MissingHeader(String),
    #[error("invalid header: {0}")]
    InvalidHeader(BoxError),
    #[error(
        "Request body length {body_len} is not aligned with size of the element {element_size}"
    )]
    WrongBodyLen { body_len: u32, element_size: usize },
    #[error(transparent)]
    InvalidJsonBody(#[from] axum::extract::rejection::JsonRejection),
    #[error("bad path: {0}")]
    BadPathString(#[source] BoxError),
    #[error(transparent)]
    BodyAlreadyExtracted(#[from] axum::extract::rejection::BodyAlreadyExtracted),
    #[error(transparent)]
    MissingExtension(#[from] axum::extract::rejection::ExtensionRejection),
    #[error(transparent)]
    HyperError(#[from] hyper::Error),
    #[error(transparent)]
    AxumError(#[from] axum::Error),
    #[error("parse error: {0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("could not forward messages: {0}")]
    SendError(BoxError),
    #[error("failed to receive response")]
    RecvError(#[from] tokio::sync::oneshot::error::RecvError),
}

impl Error {
    /// method to create an `Error::BadQueryString`
    #[must_use]
    pub fn bad_query_value(key: &str, bad_value: &str) -> Self {
        Self::BadQueryString(format!("encountered unknown query param {key}: {bad_value}").into())
    }

    /// method to create an `Error::BadPathString`
    #[must_use]
    pub fn query_id_not_found(query_id: QueryId) -> Self {
        Self::BadPathString(format!("encountered unknown query id: {}", query_id.as_ref()).into())
    }

    /// method to create an `Error::SendError`
    #[must_use]
    pub fn sender_already_exists(query_id: QueryId) -> Self {
        Self::SendError(
            format!(
                "tried to associated sender with query_id: {}, but sender already exists",
                query_id.as_ref()
            )
            .into(),
        )
    }
}

/// [`From`] implementation for `Error::BadQueryString`
impl From<axum::extract::rejection::QueryRejection> for Error {
    fn from(err: axum::extract::rejection::QueryRejection) -> Self {
        Self::BadQueryString(err.into())
    }
}

/// [`From`] implementation for `Error::BadQueryString`
impl From<crate::ff::Error> for Error {
    fn from(err: crate::ff::Error) -> Self {
        Self::BadQueryString(
            format!("unknown value found for query param field_type: {err}").into(),
        )
    }
}

/// [`From`] implementation for `Error::InvalidHeader`
impl From<std::num::ParseIntError> for Error {
    fn from(err: std::num::ParseIntError) -> Self {
        Self::InvalidHeader(err.into())
    }
}

/// [`From`] implementation for `Error::InvalidHeader`
impl From<axum::http::header::ToStrError> for Error {
    fn from(err: axum::http::header::ToStrError) -> Self {
        Self::InvalidHeader(err.into())
    }
}

/// [`From`] implementation for `Error::BadPathString`
impl From<axum::extract::rejection::PathRejection> for Error {
    fn from(err: axum::extract::rejection::PathRejection) -> Self {
        Self::BadPathString(err.into())
    }
}

/// [`From`] implementation for `Error::SendError`
/// first call `to_string` so as to drop `T` from the `Error`
impl<T> From<mpsc::error::SendError<T>> for Error {
    fn from(err: mpsc::error::SendError<T>) -> Self {
        Self::SendError(err.to_string().into())
    }
}

/// [`From`] implementation for `Error::SendError`
/// first call `to_string` to as to drop `T` from the `Error`
impl<T> From<tokio_util::sync::PollSendError<T>> for Error {
    fn from(err: tokio_util::sync::PollSendError<T>) -> Self {
        Self::SendError(err.to_string().into())
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status_code = match &self {
            Self::BadQueryString(_) | Self::BadPathString(_) | Self::MissingHeader(_) => {
                StatusCode::UNPROCESSABLE_ENTITY
            }

            Self::SerdeError(_)
            | Self::InvalidHeader(_)
            | Self::WrongBodyLen { .. }
            | Self::AxumError(_)
            | Self::InvalidJsonBody(_) => StatusCode::BAD_REQUEST,

            Self::HyperError(_)
            | Self::SendError(_)
            | Self::BodyAlreadyExtracted(_)
            | Self::MissingExtension(_)
            | Self::RecvError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status_code, self.to_string()).into_response()
    }
}
