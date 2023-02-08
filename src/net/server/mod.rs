mod error;
mod handlers;

pub use error::Error;

use crate::{
    helpers::CommandEnvelope,
    protocol::QueryId,
    sync::{Arc, Mutex},
    task::JoinHandle,
    telemetry::metrics::{web::RequestProtocolVersion, REQUESTS_RECEIVED},
};
use axum::Router;
use axum_server::{tls_rustls::RustlsConfig, Handle};
use metrics::increment_counter;
use std::collections::HashMap;
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing::Span;

use ::tokio::sync::mpsc;
#[cfg(all(feature = "shuttle", test))]
use shuttle::future as tokio;

/// MPC helper supports HTTP and HTTPS protocols. Only the latter is suitable for production,
/// http mode may be useful to debug network communication on dev machines
pub enum BindTarget {
    Http(SocketAddr),
    Https(SocketAddr, RustlsConfig),
}

/// Contains all of the state needed to start the MPC server.
pub struct MpcHelperServer {
    transport_sender: mpsc::Sender<CommandEnvelope>,
    ongoing_queries: Arc<Mutex<HashMap<QueryId, mpsc::Sender<CommandEnvelope>>>>,
}

impl MpcHelperServer {
    pub fn new(
        transport_sender: mpsc::Sender<CommandEnvelope>,
        ongoing_queries: Arc<Mutex<HashMap<QueryId, mpsc::Sender<CommandEnvelope>>>>,
    ) -> Self {
        MpcHelperServer {
            transport_sender,
            ongoing_queries,
        }
    }

    fn router(&self) -> Router {
        handlers::router(
            self.transport_sender.clone(),
            Arc::clone(&self.ongoing_queries),
        )
    }

    /// Starts a new instance of MPC helper and binds it to a given target.
    /// Returns a socket it is listening to and the join handle of the web server running.
    pub async fn bind(&self, target: BindTarget) -> (SocketAddr, JoinHandle<()>) {
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
            BindTarget::Http(addr) => tokio::spawn({
                let handle = handle.clone();
                async move {
                    axum_server::bind(addr)
                        .handle(handle)
                        .serve(svc)
                        .await
                        .expect("Failed to serve");
                }
            }),
            BindTarget::Https(addr, tls_config) => tokio::spawn({
                let handle = handle.clone();
                async move {
                    axum_server::bind_rustls(addr, tls_config)
                        .handle(handle)
                        .serve(svc)
                        .await
                        .expect("Failed to serve");
                }
            }),
        };

        let bound_addr = handle
            .listening()
            .await
            .expect("Failed to bind server to a port");
        (bound_addr, task_handle)
    }
}

/// Returns `RustlsConfig` instance configured with self-signed cert and key. Not intended to
/// use in production, therefore it is hidden behind a feature flag.
/// # Errors
/// if cert is invalid
#[cfg(any(test, feature = "self-signed-certs"))]
#[allow(dead_code)]
pub async fn tls_config_from_self_signed_cert() -> std::io::Result<RustlsConfig> {
    let cert: &'static str = r#"
-----BEGIN CERTIFICATE-----
MIIDGjCCAgICCQCHChhHY+kV3TANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJD
QTELMAkGA1UECAwCQkMxHzAdBgNVBAoMFkFudGxlcnMgYW5kIEhvb3ZlcyBMdGQx
EjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yMjA2MjAyMzE0NTdaFw0yMzA2MjAyMzE0
NTdaME8xCzAJBgNVBAYTAkNBMQswCQYDVQQIDAJCQzEfMB0GA1UECgwWQW50bGVy
cyBhbmQgSG9vdmVzIEx0ZDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3eSjoj9iWbnQy0T6E0swvba0oH6swRHNKv8m
eBPmyljhEz0IpP+D7PKiR3us1pBFaLlYJzIeGVWWY6rTThsfZmtGMP7HXXtMh9Ya
eObZ/LqBiS7gKJqiAQTaZI3lOWwnXGF4rqNENQrglwf0JL/kojgsLIgfXjOhy0ng
wb7rhy/GFYXQ8U9QUZQbvq/J4SYWZlGnLjZW4na6faImo4HoIAW3s1XlmV+XdYdS
Yw8aejmQu/8mPfSYzAP4YN3J3gOGb81Om9XrfBUAUWw0aJ+5pt3qnhe8vkzw/Vt1
8CI4SlicGySwSC0QXa3wXum4N0EE1go+yoFSbQPf2r3L2rcE5QIDAQABMA0GCSqG
SIb3DQEBCwUAA4IBAQAXZjgkd22AqIWeygTT5bgnF8fLBkI0Vo8zp8AR15TE9FBc
K/BO2+aDCloOp8D0VgHXWMZdo5DRxXV7djXDxaME00H7kajRF6UKW3NIMGO5YFcw
UUdf5GgZ5KGWjZ/6JknoypWWlFMW2Nf97CkubIX5We+jDLnuv12esBwQTXBw5oJV
jdfFfYtuVDex9fQKXa5aiBTttW4QeoGUSZT47x4RfGXAbfd2Ry9W2mhuOg7H8cZo
UsZiTnlkXIFp6VdLlfJbsbt3KXiZxrgiZX0OEEmWCtVvwswsKlY5FAMcKVsV68ok
fmJoQjCmSYjTuQrnOZMxK4tYwGqoY+vjZi4C91/P
-----END CERTIFICATE-----
   "#
    .trim();

    let key: &'static str = r#"
-----BEGIN PRIVATE KEY-----
MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDd5KOiP2JZudDL
RPoTSzC9trSgfqzBEc0q/yZ4E+bKWOETPQik/4Ps8qJHe6zWkEVouVgnMh4ZVZZj
qtNOGx9ma0Yw/sdde0yH1hp45tn8uoGJLuAomqIBBNpkjeU5bCdcYXiuo0Q1CuCX
B/Qkv+SiOCwsiB9eM6HLSeDBvuuHL8YVhdDxT1BRlBu+r8nhJhZmUacuNlbidrp9
oiajgeggBbezVeWZX5d1h1JjDxp6OZC7/yY99JjMA/hg3cneA4ZvzU6b1et8FQBR
bDRon7mm3eqeF7y+TPD9W3XwIjhKWJwbJLBILRBdrfBe6bg3QQTWCj7KgVJtA9/a
vcvatwTlAgMBAAECggEBAKYLfG/jYqOmKxqRSVm6wISW/l/Dq17nBVMRkCX3LpNp
IzSUTa27D2v2vX0kjVgaqfYODGt4U5G9vEZlBK7EGSE5UVNEtMe9hq13iGPEzIcU
we54R4HbBTQh/5OTo17vEh1NS1PUFSxkMWCTsRz3BA5oXpYMXvzNQluvsyMIzZNg
xZTEZujsuc9GLy87SkCTvbgZnB4sBrRs5L678MQN5+uF3lmd6bIDRzY2jPetDHpm
9KbtHkBosFLwt7BzBtTkbYDkpSwho+3jAUee3+SxVzgie6IZuQKKfSZ5j7CNPgVQ
PbLrC2RT4GN6AL3LoDVj3cq1qAd9jrKcSEbLNA6sT1kCgYEA+XLBFu2YXWna6NDd
GSR8AUw+ACVMvPYEOYlbFr/QFNjhxCCdZgo7iyucdoMjFXoaDWivXH00UQsG8dwh
Hq9VMbtQWHy9WnZk2eMDVAiBlQMcROUBXyamtf8u55UV7pqAR7hMWsgP5RWmyUT1
mQoFULRPBzH5bGQDv5RZaFJCw58CgYEA47ib7bzpiZNg4mMf7a0WgCee+Tr2FT0p
SBw1BjjUXxqtbSu9Jc58X+0uC3WMY1bnUbm4GUbxPX5FadFno20DB15rdADY0cC8
vBX7V5pV2gGyiAn4Oti5g8lCoB0SNFAxLfCbOhPoJp44As1tHykz9h7E7CvKJmhS
w8VLHpZzyPsCgYEAhlsTu2i/z1irqwiMffVTwVMydduhSInt3pun70njJsdmWsAC
ZyqNxbj4rjCV3gSFMcG36kYZvqkE1ZJuWFuxtHaioPaW+rmYOm92pHVsbjldqZH7
OifUVWSb++omBP08qOSQY7ksLoSJ8BBvhD2MfVqQ0lxNbt8z0aVyvqjIAxsCgYEA
q0ZSoUERNdSPbja38P/aiJFEVJgwNlFGF2J/zyo3MUDTZ+UZ4rGngk7V7vB+osje
Ou3AteJR17p9YtWJabW4LXaqwxlP+pNIYP73iDAgmlPkf8Vf2oLfJWvenKbA5m/a
TX9GgSwv07v0zMbNaD6JQnhqDGfzJ2gXt/9QPLVUaLkCgYEAlQBtUEAWIdWjKVc5
EMgsVSUkdG+N/3TT6A/f2o862yOpPh8N54Pe7UR3d+sfqwD6rKmDLKgA2KeNwEBm
6fBFT5iVlJtIa7/rFYxC/HjOYPGd5ZPyXyuiq34mmDMr5P8NDLekBHzbNQrjO4aB
ShF2TD9MWOlghJSEC6+W3nModkc=
-----END PRIVATE KEY-----
    "#
    .trim();

    RustlsConfig::from_pem(cert.as_bytes().to_vec(), key.as_bytes().to_vec()).await
}

#[cfg(all(test, not(feature = "shuttle")))]
mod e2e_tests {
    use super::*;
    use crate::{net::http_serde, test_fixture::metrics::MetricsHandle};
    use hyper::{client::HttpConnector, http::uri, StatusCode, Version};
    use hyper_tls::{native_tls::TlsConnector, HttpsConnector};
    use metrics_util::debugging::Snapshotter;
    use tracing::Level;

    async fn init_server() -> SocketAddr {
        let (transport_sender, _) = mpsc::channel(1);
        let ongoing_queries = Arc::new(Mutex::new(HashMap::new()));
        let server = MpcHelperServer::new(transport_sender, Arc::clone(&ongoing_queries));
        let (addr, _) = server
            .bind(BindTarget::Http("0.0.0.0:0".parse().unwrap()))
            .await;
        addr
    }

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
        let addr = init_server().await;

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
        // https server
        let (transport_sender, _) = mpsc::channel(1);
        let ongoing_queries = Arc::new(Mutex::new(HashMap::new()));
        let server = MpcHelperServer::new(transport_sender, Arc::clone(&ongoing_queries));
        let config = tls_config_from_self_signed_cert().await.unwrap();
        let (addr, _) = server
            .bind(BindTarget::Https("0.0.0.0:0".parse().unwrap(), config))
            .await;

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
        let addr = init_server().await;

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
        let addr = init_server().await;

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
