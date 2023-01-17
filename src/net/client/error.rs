#[derive(thiserror::Error, Debug)]
#[allow(clippy::module_name_repetitions)] // follows standard naming convention
pub enum Error {
    #[error(transparent)]
    InvalidUri(#[from] hyper::http::uri::InvalidUri),

    #[error("request returned {status}: {reason}")]
    FailedRequest {
        status: hyper::StatusCode,
        reason: String,
    },

    #[error(transparent)]
    HyperPassthrough(#[from] hyper::Error),
    #[error(transparent)]
    HyperHttpPassthrough(#[from] hyper::http::Error),
    #[error(transparent)]
    SerdeJsonPassthrough(#[from] serde_json::Error),
}

impl Error {
    /// Extracts the body from the response to use as error message.
    /// Because the body is in a future, cannot use [`From`] trait
    pub async fn from_failed_resp<B>(resp: hyper::Response<B>) -> Self
    where
        B: hyper::body::HttpBody,
        Error: From<<B as hyper::body::HttpBody>::Error>,
    {
        let status = resp.status();
        assert!(status.is_client_error() || status.is_server_error()); // must be failure
        hyper::body::to_bytes(resp.into_body())
            .await
            .map_or_else(Into::into, |reason_bytes| Error::FailedRequest {
                status,
                reason: String::from_utf8_lossy(&reason_bytes).to_string(),
            })
    }
}
