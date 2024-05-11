mod create;
mod input;
mod prepare;
mod results;
mod status;
mod step;

use axum::{
    response::{IntoResponse, Response},
    Router,
};
use futures_util::{
    future::{ready, Either, Ready},
    FutureExt,
};
use hyper::{Request, StatusCode};
use tower::{layer::layer_fn, Service};

use crate::{
    net::{server::ClientIdentity, HttpTransport},
    sync::Arc,
};

/// Construct router for IPA query web service
///
/// In principle, this web service could be backed by either an HTTP-interconnected helper network or
/// an in-memory helper network. These are the APIs used by external callers (report collectors) to
/// examine attribution results.
pub fn query_router(transport: Arc<HttpTransport>) -> Router {
    Router::new()
        .merge(create::router(Arc::clone(&transport)))
        .merge(input::router(Arc::clone(&transport)))
        .merge(status::router(Arc::clone(&transport)))
        .merge(results::router(transport))
}

/// Construct router for helper-to-helper communications
///
/// This only makes sense in the context of an HTTP-interconnected helper network. These APIs are
/// called by peer helpers to exchange MPC step data, and by whichever helper is the leader for a
/// particular query, to coordinate servicing that query.
//
// It might make sense to split the query and h2h handlers into two modules.
pub fn h2h_router(transport: Arc<HttpTransport>) -> Router {
    Router::new()
        .merge(prepare::router(Arc::clone(&transport)))
        .merge(step::router(transport))
        .layer(layer_fn(HelperAuthentication::new))
}

/// Returns HTTP 401 Unauthorized if the request does not have valid authentication.
///
/// Authentication information is carried via the `ClientIdentity` request extension. The extension
/// is populated (by `ClientCertRecognizingAcceptor` / `SetClientIdentityFromCertificate`) when a
/// valid client certificate is presented. When using plain HTTP (only for testing), the extension
/// is populated by `SetClientIdentityFromHeader`.
///
/// Note that there are two partially redundant mechanisms enforcing authentication for
/// helper-to-helper RPC. This middleware is one. The other is the argument of type
/// `Extension<ClientIdentity>` to the handler.  Even without this middleware, unauthenticated
/// requests would not have this request extension, causing axum to fail the request with
/// `ExtensionRejection::MissingExtension`, however, this would return a 500 error instead of 401.
#[derive(Clone)]
pub struct HelperAuthentication<S> {
    inner: S,
}

impl<S> HelperAuthentication<S> {
    fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<B, S: Service<Request<B>, Response = Response>> Service<Request<B>>
    for HelperAuthentication<S>
{
    type Response = Response;
    type Error = S::Error;
    type Future = Either<S::Future, Ready<Result<Response, S::Error>>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        match req.extensions().get() {
            Some(ClientIdentity(_)) => self.inner.call(req).left_future(),
            None => ready(Ok((
                StatusCode::UNAUTHORIZED,
                "This API requires the client helper to authenticate",
            )
                .into_response()))
            .right_future(),
        }
    }
}

#[cfg(all(test, unit_test))]
pub mod test_helpers {
    use std::{any::Any, sync::Arc};

    use hyper::{http::request, StatusCode};

    use crate::{
        helpers::{HelperIdentity, RequestHandler},
        net::test::TestServer,
    };

    /// Helper trait for optionally adding an extension to a request.
    pub trait MaybeExtensionExt {
        fn maybe_extension<T: Any + Send + Sync + 'static>(self, extension: Option<T>) -> Self;
    }

    impl MaybeExtensionExt for request::Builder {
        fn maybe_extension<T: Any + Send + Sync + 'static>(self, extension: Option<T>) -> Self {
            if let Some(extension) = extension {
                self.extension(extension)
            } else {
                self
            }
        }
    }

    // Intended to be used for a request that will fail Starts a [`TestServer`] and gets response
    // from the server, and compare its [`StatusCode`] with what is expected.
    pub async fn assert_fails_with(req: hyper::Request<hyper::Body>, expected_status: StatusCode) {
        let test_server = TestServer::builder().build().await;
        let resp = test_server.server.handle_req(req).await;
        assert_eq!(resp.status(), expected_status);
    }

    pub async fn assert_success_with(
        req: hyper::Request<hyper::Body>,
        handler: Arc<dyn RequestHandler<Identity = HelperIdentity>>,
    ) -> Vec<u8> {
        let test_server = TestServer::builder()
            .with_request_handler(handler)
            .build()
            .await;
        let resp = test_server.server.handle_req(req).await;
        let status = resp.status();
        let body_bytes = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        assert_eq!(StatusCode::OK, status);
        body_bytes.to_vec()
    }
}
