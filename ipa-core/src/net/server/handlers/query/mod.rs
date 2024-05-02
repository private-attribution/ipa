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
    use std::any::Any;

    use futures_util::future::poll_immediate;
    use hyper::{http::request, service::Service, StatusCode};
    use tower::ServiceExt;

    use crate::net::test::TestServer;

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

    /// types that implement `IntoFailingReq` are intended to induce some failure in the process of
    /// axum routing. Pair with `assert_req_fails_with` to detect specific [`StatusCode`] failures.
    pub trait IntoFailingReq {
        fn into_req(self, port: u16) -> hyper::Request<hyper::Body>;
    }

    /// Intended to be used for a request that will fail during axum routing. When passed a known
    /// bad request via `IntoFailingReq`, get a response from the server, and compare its
    /// [`StatusCode`] with what is expected.
    pub async fn assert_req_fails_with<I: IntoFailingReq>(req: I, expected_status: StatusCode) {
        let TestServer { server, .. } = TestServer::default().await;

        let mut router = server.router();
        let ready = poll_immediate(router.ready()).await.unwrap().unwrap();
        let resp = poll_immediate(ready.call(req.into_req(0)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.status(), expected_status);
    }
}
