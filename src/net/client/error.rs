use crate::net::client::MpcClientError::FailedRequest;
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
#[allow(clippy::module_name_repetitions)] // follows standard naming convention
pub enum MpcClientError {
    #[error(transparent)]
    InvalidHostAddress(#[from] axum::http::uri::InvalidUri),

    #[error(transparent)]
    NetworkConnection(#[from] hyper::Error),

    #[error("request returned {status}: {reason}")]
    FailedRequest {
        status: hyper::StatusCode,
        reason: String,
    },

    #[error(transparent)]
    AxumError(#[from] axum::http::Error),
}

impl MpcClientError {
    pub async fn from_failed_resp<B>(resp: hyper::Response<B>) -> Self
    where
        B: hyper::body::HttpBody,
        MpcClientError: From<<B as hyper::body::HttpBody>::Error>,
    {
        let status = resp.status();
        assert!(status.is_client_error() || status.is_server_error()); // must be failure
        hyper::body::to_bytes(resp.into_body())
            .await
            .map_or_else(Into::into, |reason_bytes| FailedRequest {
                status,
                reason: String::from_utf8_lossy(&reason_bytes).to_string(),
            })
    }
}
