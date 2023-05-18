mod handlers;

use crate::{
    config::{NetworkConfig, ServerConfig},
    net::{Error, HttpTransport},
    sync::Arc,
    task::JoinHandle,
    telemetry::metrics::{web::RequestProtocolVersion, REQUESTS_RECEIVED},
};
use axum::{routing::IntoMakeService, Router};
use axum_server::{
    accept::Accept,
    service::{MakeServiceRef, SendService},
    Handle, HttpConfig, Server,
};
use futures::Future;
use hyper::{server::conn::AddrStream, Request};
use metrics::increment_counter;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use tower_http::trace::TraceLayer;
use tracing::Span;

use ::tokio::io::{AsyncRead, AsyncWrite};

#[cfg(all(feature = "shuttle", test))]
use shuttle::future as tokio;

pub trait TracingSpanMaker: Send + Sync + Clone + 'static {
    fn make_span(&self) -> Span;
}

impl<T: TracingSpanMaker> TracingSpanMaker for Option<T> {
    fn make_span(&self) -> Span {
        if let Some(h) = self {
            h.make_span()
        } else {
            tracing::trace_span!("")
        }
    }
}

impl TracingSpanMaker for () {
    fn make_span(&self) -> Span {
        tracing::trace_span!("")
    }
}

/// IPA helper web service
///
/// `MpcHelperServer` handles requests from both peer helpers and external clients.
pub struct MpcHelperServer {
    transport: Arc<HttpTransport>,
    config: ServerConfig,
    _network_config: NetworkConfig,
}

impl MpcHelperServer {
    pub fn new(
        transport: Arc<HttpTransport>,
        config: ServerConfig,
        network_config: NetworkConfig,
    ) -> Self {
        MpcHelperServer {
            transport,
            config,
            _network_config: network_config,
        }
    }

    fn router(&self) -> Router {
        handlers::router(Arc::clone(&self.transport))
    }

    #[cfg(all(test, feature = "in-memory-infra", not(feature = "shuttle")))]
    async fn handle_req(&self, req: hyper::Request<hyper::Body>) -> axum::response::Response {
        let mut router = self.router();
        let router = tower::ServiceExt::ready(&mut router).await.unwrap();
        hyper::service::Service::call(router, req).await.unwrap()
    }

    /// Starts the MPC helper service.
    ///
    /// If `listener` is provided, listens on the supplied socket. This is used for tests which want
    /// to use a dynamically assigned free port, but need to know the port number when generating
    /// helper configurations. If `listener` is not provided, binds according to the server
    /// configuration supplied to `new`.
    ///
    /// Returns the `SocketAddr` of the server socket and the `JoinHandle` of the server task.
    ///
    /// # Panics
    /// If the server TLS configuration is not valid.
    pub async fn start_on<T: TracingSpanMaker>(
        &self,
        listener: Option<TcpListener>,
        tracing: T,
    ) -> (SocketAddr, JoinHandle<()>) {
        // This should probably come from the server config.
        // Note that listening on 0.0.0.0 requires accepting a MacOS security
        // warning on each test run.
        #[cfg(test)]
        const BIND_ADDRESS: Ipv4Addr = Ipv4Addr::LOCALHOST;
        #[cfg(not(test))]
        const BIND_ADDRESS: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

        let svc = self
            .router()
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(move |_request: &hyper::Request<hyper::Body>| {
                        tracing.make_span()
                    })
                    .on_request(|request: &hyper::Request<hyper::Body>, _: &Span| {
                        increment_counter!(RequestProtocolVersion::from(request.version()));
                        increment_counter!(REQUESTS_RECEIVED);
                    }),
            )
            .into_make_service();
        let handle = Handle::new();

        let task_handle = match (self.config.disable_https, listener) {
            (true, Some(listener)) => {
                spawn_server(axum_server::from_tcp(listener), handle.clone(), svc).await
            }
            (true, None) => {
                let addr = SocketAddr::new(BIND_ADDRESS.into(), self.config.port.unwrap_or(0));
                spawn_server(axum_server::bind(addr), handle.clone(), svc).await
            }
            (false, Some(listener)) => {
                let rustls_config = self
                    .config
                    .as_rustls_config()
                    .await
                    .expect("invalid TLS configuration");
                spawn_server(
                    axum_server::from_tcp_rustls(listener, rustls_config),
                    handle.clone(),
                    svc,
                )
                .await
            }
            (false, None) => {
                let addr = SocketAddr::new(BIND_ADDRESS.into(), self.config.port.unwrap_or(0));
                let rustls_config = self
                    .config
                    .as_rustls_config()
                    .await
                    .expect("invalid TLS configuration");
                spawn_server(
                    axum_server::bind_rustls(addr, rustls_config),
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
        #[cfg(not(test))] // reduce spam in test output
        tracing::info!(
            "server listening on {}://{}",
            if self.config.disable_https {
                "http"
            } else {
                "https"
            },
            bound_addr,
        );
        (bound_addr, task_handle)
    }

    pub fn start<T: TracingSpanMaker>(
        &self,
        tracing: T,
    ) -> impl Future<Output = (SocketAddr, JoinHandle<()>)> + '_ {
        self.start_on(None, tracing)
    }
}

async fn spawn_server<A>(
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
                // TODO: configuration
                .http_config(
                    HttpConfig::default()
                        .http2_max_concurrent_streams(Some(256))
                        .build(),
                )
                .handle(handle)
                .serve(svc)
                .await
                .expect("Failed to serve");
        }
    })
}

#[cfg(all(test, not(feature = "shuttle"), feature = "in-memory-infra"))]
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
        let TestServer { addr, .. } = TestServer::builder().disable_https().build().await;

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
        let TestServer { addr, .. } = TestServer::builder().build().await;

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
        let TestServer { addr, .. } = TestServer::builder()
            .disable_https() // required because this test uses a vanilla hyper client
            .with_metrics(handle.clone())
            .build()
            .await;

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
        let TestServer { addr, .. } = TestServer::builder()
            .disable_https() // required because this test uses vanilla hyper clients
            .with_metrics(handle.clone())
            .build()
            .await;

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
