mod handlers;

use hyper::{server::conn::AddrStream, Request};

use crate::{
    net::{Error, HttpTransport},
    sync::Arc,
    task::JoinHandle,
    telemetry::metrics::{web::RequestProtocolVersion, REQUESTS_RECEIVED},
};
use axum::{routing::IntoMakeService, Router};
use axum_server::{
    accept::Accept,
    service::{MakeServiceRef, SendService},
    tls_rustls::RustlsConfig,
    Handle, Server,
};
use metrics::increment_counter;
use std::net::{SocketAddr, TcpListener};
use tower_http::trace::TraceLayer;
use tracing::Span;

use ::tokio::io::{AsyncRead, AsyncWrite};
#[cfg(all(feature = "shuttle", test))]
use shuttle::future as tokio;

/// MPC helper supports HTTP and HTTPS protocols. Only the latter is suitable for production,
/// http mode may be useful to debug network communication on dev machines
pub enum BindTarget {
    Http(SocketAddr),
    Https(SocketAddr, RustlsConfig),
    HttpListener(TcpListener),
}

/// IPA helper web service
///
/// `MpcHelperServer` handles requests from both peer helpers and external clients.
pub struct MpcHelperServer {
    transport: Arc<HttpTransport>,
}

impl MpcHelperServer {
    pub fn new(transport: Arc<HttpTransport>) -> Self {
        MpcHelperServer { transport }
    }

    fn router(&self) -> Router {
        handlers::router(Arc::clone(&self.transport))
    }

    /// Starts a new instance of MPC helper and binds it to a given target.
    /// Returns a socket it is listening to and the join handle of the web server running.
    pub async fn bind(&self, target: BindTarget) -> (SocketAddr, JoinHandle<()>) {
        async fn serve<A>(
            server: Server<A>,
            handle: Handle,
            svc: IntoMakeService<Router>,
        ) -> JoinHandle<()>
        where
            A: Accept<
                    AddrStream,
                    <IntoMakeService<Router> as MakeServiceRef<
                        AddrStream,
                        hyper::Request<hyper::Body>,
                    >>::Service,
                > + Clone
                + Send
                + Sync
                + 'static,
            A::Stream: AsyncRead + AsyncWrite + Unpin + Send,
            A::Service: SendService<Request<hyper::Body>> + Send,
            A::Future: Send,
        {
            tokio::spawn({
                async move {
                    server
                        .handle(handle)
                        .serve(svc)
                        .await
                        .expect("Failed to serve");
                }
            })
        }

        let svc = self
            .router()
            .layer(TraceLayer::new_for_http().on_request(
                |request: &hyper::Request<hyper::Body>, _span: &Span| {
                    increment_counter!(RequestProtocolVersion::from(request.version()));
                    increment_counter!(REQUESTS_RECEIVED);
                },
            ))
            .into_make_service();
        let handle = Handle::new();

        let task_handle = match target {
            BindTarget::Http(addr) => serve(axum_server::bind(addr), handle.clone(), svc).await,
            BindTarget::HttpListener(listener) => {
                serve(axum_server::from_tcp(listener), handle.clone(), svc).await
            }
            BindTarget::Https(addr, tls_config) => {
                serve(
                    axum_server::bind_rustls(addr, tls_config),
                    handle.clone(),
                    svc,
                )
                .await
            }
        };

        let bound_addr = handle
            .listening()
            .await
            .expect("Failed to bind server to a port");
        (bound_addr, task_handle)
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod e2e_tests {
    use super::*;
    use crate::{
        net::{http_serde, test::TestServer},
        test_fixture::metrics::MetricsHandle,
    };
    use hyper::{client::HttpConnector, http::uri, StatusCode, Version};
    use hyper_tls::{native_tls::TlsConnector, HttpsConnector};
    use metrics_util::debugging::Snapshotter;
    use std::collections::HashMap;
    use tracing::Level;

    fn expected_req(host: String) -> http_serde::echo::Request {
        http_serde::echo::Request::new(
            HashMap::from([
                (String::from("foo"), String::from("1")),
                (String::from("bar"), String::from("2")),
            ]),
            HashMap::from([(String::from("host"), host)]),
        )
    }

    fn http_req(
        expected: &http_serde::echo::Request,
        scheme: uri::Scheme,
        authority: String,
    ) -> hyper::Request<hyper::Body> {
        expected
            .clone()
            .try_into_http_request(scheme, uri::Authority::try_from(authority).unwrap())
            .unwrap()
    }

    #[tokio::test]
    async fn can_do_http() {
        // server
        let TestServer { addr, .. } = TestServer::default().await;

        // client
        let client = hyper::Client::new();

        // request
        let expected = expected_req(addr.to_string());

        let req = http_req(&expected, uri::Scheme::HTTP, addr.to_string());
        let resp = client.request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let resp_body: http_serde::echo::Request = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(expected, resp_body);
    }

    #[tokio::test]
    async fn can_do_https() {
        let TestServer { addr, .. } = TestServer::builder().https().build().await;

        // self-signed cert CN is "localhost", therefore request authority must not use the ip address
        let authority = format!("localhost:{}", addr.port());

        // https client
        let conn = TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let mut http = HttpConnector::new();
        http.enforce_http(false);

        let https = HttpsConnector::<HttpConnector>::from((http, conn.into()));
        let client = hyper::Client::builder().build(https);

        // request
        let expected = expected_req(authority.clone());
        let req = http_req(&expected, uri::Scheme::HTTPS, authority);
        let resp = client.request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let resp_body: http_serde::echo::Request = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(expected, resp_body);
    }

    /// Ensures that server tracks number of requests it received and emits a corresponding metric.
    /// In order for this test not to be flaky, we rely on tokio::test macro to set up a
    /// new runtime per test (which it currently does) and set up metric recorders per thread (done
    /// by this test). It is also tricky to make it work in a multi-threaded environment - I haven't
    /// tested that, so better to stick with default behavior of tokio:test macro
    #[tokio::test]
    async fn requests_received_metric() {
        let handle = MetricsHandle::new(Level::INFO);

        // server
        let TestServer { addr, .. } = TestServer::default().await;

        // client
        let client = hyper::Client::new();

        // request
        let expected = expected_req(addr.to_string());

        let snapshot = Snapshotter::current_thread_snapshot();
        assert!(snapshot.is_none());

        let request_count = 10;
        for _ in 0..request_count {
            let req = http_req(&expected, uri::Scheme::HTTP, addr.to_string());
            let response = client.request(req).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        assert_eq!(
            Some(request_count),
            handle.get_counter_value(REQUESTS_RECEIVED)
        );
    }

    #[tokio::test]
    async fn request_version_metric() {
        let handle = MetricsHandle::new(Level::INFO);

        // server
        let TestServer { addr, .. } = TestServer::default().await;

        // request
        let expected = expected_req(addr.to_string());

        // make HTTP/1.1 request
        let client = hyper::Client::new();
        let req = http_req(&expected, uri::Scheme::HTTP, addr.to_string());
        let response = client.request(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // make HTTP/2 request
        let client = hyper::Client::builder().http2_only(true).build_http();
        let req = http_req(&expected, uri::Scheme::HTTP, addr.to_string());
        let response = client.request(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        assert_eq!(
            Some(1),
            handle.get_counter_value(RequestProtocolVersion::from(Version::HTTP_11))
        );
        assert_eq!(
            Some(1),
            handle.get_counter_value(RequestProtocolVersion::from(Version::HTTP_2))
        );
        assert_eq!(
            None,
            handle.get_counter_value(RequestProtocolVersion::from(Version::HTTP_3))
        );
    }
}
