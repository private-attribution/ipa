use axum::{Extension, Router, routing::get};
use hyper::StatusCode;

use crate::{
    helpers::{BodyStream, routing::RouteId},
    net::{
        Error, MpcHttpTransport,
        http_serde::{self},
    },
};

/// Takes details from the HTTP request and creates a `[TransportCommand]::CreateQuery` that is sent
/// to the [`HttpTransport`].
async fn handler(transport: Extension<MpcHttpTransport>) -> Result<Vec<u8>, Error> {
    match transport
        .dispatch(RouteId::Metrics, BodyStream::empty())
        .await
    {
        Ok(resp) => Ok(resp.into_body()),
        Err(err) => Err(Error::application(StatusCode::INTERNAL_SERVER_ERROR, err)),
    }
}

pub fn router(transport: MpcHttpTransport) -> Router {
    Router::new()
        .route(http_serde::metrics::AXUM_PATH, get(handler))
        .layer(Extension(transport))
}

#[cfg(all(test, unit_test))]
mod tests {
    use axum::{
        body::Body,
        http::uri::{self, Authority, Scheme},
    };

    use super::*;
    use crate::{
        helpers::{HelperIdentity, HelperResponse, make_owned_handler, routing::Addr},
        net::server::handlers::query::test_helpers::assert_success_with,
    };

    #[tokio::test]
    async fn happy_case() {
        let handler = make_owned_handler(
            move |addr: Addr<HelperIdentity>, _data: BodyStream| async move {
                let RouteId::Metrics = addr.route else {
                    panic!("unexpected call");
                };
                Ok(HelperResponse::from(Vec::new()))
            },
        );
        let uri = uri::Builder::new()
            .scheme(Scheme::HTTP)
            .authority(Authority::from_static("localhost"))
            .path_and_query(String::from("/metrics"))
            .build()
            .unwrap();
        let req = hyper::Request::get(uri).body(Body::empty()).unwrap();
        assert_success_with(req, handler).await;
    }
}
