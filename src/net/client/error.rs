use crate::net::client::MpcHelperClientError::FailedRequest;
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
#[allow(clippy::module_name_repetitions)] // follows standard naming convention
pub enum MpcHelperClientError {
    #[error(transparent)]
    InvalidUri(#[from] hyper::http::uri::InvalidUri),

    #[error(transparent)]
    NetworkConnection(#[from] hyper::Error),

    #[error("request returned {status}: {reason}")]
    FailedRequest {
        status: hyper::StatusCode,
        reason: String,
    },

    #[error(transparent)]
    HttpError(#[from] hyper::http::Error),
}

impl MpcHelperClientError {
    pub async fn from_failed_resp<B>(resp: hyper::Response<B>) -> Self
    where
        B: hyper::body::HttpBody,
        MpcHelperClientError: From<<B as hyper::body::HttpBody>::Error>,
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
