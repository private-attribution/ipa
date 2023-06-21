use crate::{error::BoxError, protocol::QueryId};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

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
    #[error("query id not found: {}", .0.as_ref())]
    QueryIdNotFound(QueryId),
    #[error(transparent)]
    HyperPassthrough(#[from] hyper::Error),
    #[error(transparent)]
    HyperHttpPassthrough(#[from] hyper::http::Error),
    #[error(transparent)]
    AxumPassthrough(#[from] axum::Error),
    #[error("parse error: {0}")]
    SerdePassthrough(#[from] serde_json::Error),
    #[error(transparent)]
    InvalidUri(#[from] hyper::http::uri::InvalidUri),
    // `FailedHttpRequest` and `Application` are for the same errors, with slightly different
    // representation. Server side code uses `Application` and client side code uses
    // `FailedHttpRequest`.
    //
    // At some point, we might want the RPC mechanism to have the ability to convey detailed error
    // information back to clients in machine-parsable form. If we did that, then these two error
    // variants could be combined. Alternatively, successful delivery of an application layer
    // failure could be viewed as not a transport error at all.
    #[error("request returned {status}: {reason}")]
    FailedHttpRequest {
        status: hyper::StatusCode,
        reason: String,
    },
    #[error("{error}")]
    Application { code: StatusCode, error: BoxError },
}

impl Error {
    /// method to create an `Error::BadQueryString`
    #[must_use]
    pub fn bad_query_value(key: &str, bad_value: &str) -> Self {
        Self::BadQueryString(format!("encountered unknown query param {key}: {bad_value}").into())
    }

    /// Extracts the body from the response to use as error message.
    /// Because the body is in a future, cannot use [`From`] trait
    ///
    /// # Panics
    /// If the response is not a failure (4xx/5xx status)
    pub async fn from_failed_resp<B>(resp: hyper::Response<B>) -> Self
    where
        B: hyper::body::HttpBody,
        Error: From<<B as hyper::body::HttpBody>::Error>,
    {
        let status = resp.status();
        assert!(status.is_client_error() || status.is_server_error()); // must be failure
        hyper::body::to_bytes(resp.into_body())
            .await
            .map_or_else(Into::into, |reason_bytes| Error::FailedHttpRequest {
                status,
                reason: String::from_utf8_lossy(&reason_bytes).to_string(),
            })
    }

    #[must_use]
    pub fn application<E: Into<BoxError>>(code: StatusCode, error: E) -> Self {
        Self::Application {
            code,
            error: error.into(),
        }
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

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status_code = match self {
            Self::BadQueryString(_) | Self::BadPathString(_) | Self::MissingHeader(_) => {
                StatusCode::UNPROCESSABLE_ENTITY
            }

            Self::SerdePassthrough(_)
            | Self::InvalidHeader(_)
            | Self::WrongBodyLen { .. }
            | Self::AxumPassthrough(_)
            | Self::InvalidJsonBody(_)
            | Self::QueryIdNotFound(_) => StatusCode::BAD_REQUEST,

            Self::HyperPassthrough(_)
            | Self::HyperHttpPassthrough(_)
            | Self::FailedHttpRequest { .. }
            | Self::InvalidUri(_)
            | Self::BodyAlreadyExtracted(_)
            | Self::MissingExtension(_) => StatusCode::INTERNAL_SERVER_ERROR,

            Self::Application { code, .. } => code,
        };

        (status_code, self.to_string()).into_response()
    }
}
