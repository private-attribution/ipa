use axum::{body::Body, BoxError};
use http_body_util::BodyExt;
use hyper::Uri;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{client::legacy::Client, rt::{TokioExecutor, TokioTimer}};

use crate::{helpers::BodyStream, net::Error};

/// Download query input from a remote URL.
pub async fn stream_query_input_from_url(uri: &Uri) -> Result<BodyStream, Error> {
    let mut builder = Client::builder(TokioExecutor::new());
    // the following timer is necessary for http2, in particular for any timeouts
    // and waits the clients will need to make
    // TODO: implement IpaTimer to allow wrapping other than Tokio runtimes
    builder.timer(TokioTimer::new());
    let client = builder.build::<_, Body>(
        HttpsConnectorBuilder::default()
            .with_native_roots()
            .expect("System truststore is required")
            .https_only()
            .enable_all_versions()
            .build()
    );

    let resp = client.get(uri.clone())
        .await
        .map_err(|inner| Error::ConnectError { dest: uri.to_string(), inner })?;

    if !resp.status().is_success() {
        let status = resp.status();
        assert!(status.is_client_error() || status.is_server_error()); // must be failure
        return Err(
            axum::body::to_bytes(Body::new(resp.into_body()), 36_000_000) // Roughly 36mb
                .await
                .map_or_else(Into::into, |reason_bytes| Error::FailedHttpRequest {
                    dest: uri.to_string(),
                    status,
                    reason: String::from_utf8_lossy(&reason_bytes).to_string(),
                })
        );
    }

    Ok(BodyStream::from_bytes_stream(resp.into_body().map_err(BoxError::from).into_data_stream()))
}

/*
pub async fn stream_query_input(query_input: QueryInput) -> Result<BodyStream, Error> {
    match query_input {
        QueryInput::Inline { input_stream, .. } => Ok(input_stream),
        QueryInput::FromUrl { url, .. } => stream_query_input_from_url(&url).await,
    }
}
*/
