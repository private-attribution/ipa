pub mod handlers;

use crate::sync::{Arc, Mutex};
use crate::task::JoinHandle;
use crate::{
    error::BoxError,
    helpers::{old_http::HttpNetwork, old_network::MessageChunks},
    net::LastSeenMessages,
    protocol::QueryId,
    telemetry::metrics::{RequestProtocolVersion, REQUESTS_RECEIVED},
};
use ::tokio::sync::mpsc;
use axum::{
    extract::rejection::QueryRejection,
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Router,
};
use axum_server::{tls_rustls::RustlsConfig, Handle};
use hyper::{Body, Request, StatusCode};
use metrics::increment_counter;
use std::collections::{hash_map::Entry, HashMap};
use std::fmt::Debug;
use std::net::SocketAddr;
use thiserror::Error;
use tower_http::trace::TraceLayer;
use tracing::Span;

#[cfg(all(feature = "shuttle", test))]
use shuttle::future as tokio;

#[derive(Error, Debug)]
pub enum MpcHelperServerError {
    #[error(transparent)]
    BadQueryString(#[from] QueryRejection),
    #[error("header not found: {0}")]
    MissingHeader(String),
    #[error("invalid header: {0}")]
    InvalidHeader(BoxError),
    #[error(
        "Request body length {body_len} is not aligned with size of the element {element_size}"
    )]
    WrongBodyLen { body_len: u32, element_size: usize },
    #[error("bad path: {0}")]
    BadPathString(#[source] BoxError),
    #[error(transparent)]
    BodyAlreadyExtracted(#[from] axum::extract::rejection::BodyAlreadyExtracted),
    #[error(transparent)]
    MissingExtension(#[from] axum::extract::rejection::ExtensionRejection),
    #[error(transparent)]
    HyperError(#[from] hyper::Error),
    #[error("parse error: {0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("could not forward messages: {0}")]
    SendError(BoxError),
}

impl MpcHelperServerError {
    #[must_use]
    pub fn query_id_not_found(query_id: QueryId) -> Self {
        Self::BadPathString(format!("encountered unknown query id: {}", query_id.as_ref()).into())
    }

    #[must_use]
    pub fn sender_already_exists(query_id: QueryId) -> Self {
        Self::SendError(
            format!(
                "tried to associated sender with query_id: {}, but sender already exists",
                query_id.as_ref()
            )
            .into(),
        )
    }
}

impl From<std::num::ParseIntError> for MpcHelperServerError {
    fn from(err: std::num::ParseIntError) -> Self {
        Self::InvalidHeader(err.into())
    }
}

impl From<axum::http::header::ToStrError> for MpcHelperServerError {
    fn from(err: axum::http::header::ToStrError) -> Self {
        Self::InvalidHeader(err.into())
    }
}

impl From<axum::extract::rejection::PathRejection> for MpcHelperServerError {
    fn from(err: axum::extract::rejection::PathRejection) -> Self {
        Self::BadPathString(err.into())
    }
}

/// first call `to_string` so as to drop `T` from the [`MpcHelperServerError`]
impl<T> From<mpsc::error::SendError<T>> for MpcHelperServerError {
    fn from(err: mpsc::error::SendError<T>) -> Self {
        Self::SendError(err.to_string().into())
    }
}

/// first call `to_string` to as to drop `T` from the [`MpcHelperServerError`]
impl<T> From<tokio_util::sync::PollSendError<T>> for MpcHelperServerError {
    fn from(err: tokio_util::sync::PollSendError<T>) -> Self {
        Self::SendError(err.to_string().into())
    }
}

impl IntoResponse for MpcHelperServerError {
    fn into_response(self) -> Response {
        let status_code = match &self {
            Self::BadQueryString(_) | Self::BadPathString(_) | Self::MissingHeader(_) => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
            Self::SerdeError(_) | Self::InvalidHeader(_) | Self::WrongBodyLen { .. } => {
                StatusCode::BAD_REQUEST
            }
            Self::HyperError(_)
            | Self::SendError(_)
            | Self::BodyAlreadyExtracted(_)
            | Self::MissingExtension(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status_code, self.to_string()).into_response()
    }
}

/// Provides a mapping of [`QueryId`]s to senders that forward data to a [`HttpNetwork`]. Every time a
/// new query is started, a [`HttpNetwork`] is created to handle communication for that query. When the
/// server receives a request, it must know which [`HttpNetwork`] to forward that request to, so it
/// holds this mapping to accomplish that.
///
/// Is shareable by `clone()`ing.
#[derive(Clone)]
pub struct MessageSendMap {
    networks: Arc<Mutex<HashMap<QueryId, HttpNetwork>>>,
}

impl MessageSendMap {
    /// returns the sender for a given query
    /// # Errors
    /// if sender does not exist
    /// # Panics
    /// if mutex is poisoned
    pub fn get(
        &self,
        query_id: QueryId,
    ) -> Result<mpsc::Sender<MessageChunks>, MpcHelperServerError> {
        self.networks.lock().unwrap().get(&query_id).map_or_else(
            || Err(MpcHelperServerError::query_id_not_found(query_id)),
            |network| Ok(network.message_stream_sender()),
        )
    }

    /// adds a sender for a given query
    /// # Errors
    /// if entry already exists
    /// # Panics
    /// if mutex is poisoned
    pub fn insert_if_not_present(
        &self,
        query_id: QueryId,
        network: HttpNetwork,
    ) -> Result<(), MpcHelperServerError> {
        match self.networks.lock().unwrap().entry(query_id) {
            Entry::Occupied(_) => Err(MpcHelperServerError::sender_already_exists(query_id)),
            Entry::Vacant(entry) => {
                entry.insert(network);
                Ok(())
            }
        }
    }

    /// removes a sender for a given query
    /// # Panics
    /// if mutex is poisoned
    pub fn remove(&self, query_id: QueryId) {
        self.networks.lock().unwrap().remove(&query_id);
    }

    /// initialize with a [`QueryId`] already inserted.
    /// Intended to be used only in tests
    #[cfg(test)]
    #[must_use]
    pub fn filled(network: HttpNetwork) -> MessageSendMap {
        MessageSendMap {
            networks: Arc::new(Mutex::new([(QueryId, network)].into())),
        }
    }
}

impl Default for MessageSendMap {
    fn default() -> Self {
        Self {
            networks: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

/// MPC helper supports HTTP and HTTPS protocols. Only the latter is suitable for production,
/// http mode may be useful to debug network communication on dev machines
pub enum BindTarget {
    Http(SocketAddr),
    Https(SocketAddr, RustlsConfig),
}

/// Contains all of the state needed to start the MPC server.
/// For now, stub out gateway with simple send/receive
/// TODO (ts): replace stub with real thing when `Network` is implemented
pub struct MpcHelperServer {
    message_send_map: MessageSendMap,
    last_seen_messages: LastSeenMessages,
}

impl MpcHelperServer {
    #[must_use]
    pub fn new(message_send_map: MessageSendMap) -> Self {
        MpcHelperServer {
            message_send_map,
            last_seen_messages: LastSeenMessages::default(),
        }
    }

    /// Axum router definition for MPC helper endpoint
    #[must_use]
    pub(crate) fn router(&self) -> Router {
        Router::new()
            // query handler
            .route("/query/:query_id/step/*step", post(handlers::query_handler))
            .layer(middleware::from_fn(handlers::obtain_permit_mw))
            .layer(Extension(self.last_seen_messages.clone()))
            .layer(Extension(self.message_send_map.clone()))
            // echo
            .route("/echo", get(handlers::echo_handler))
    }

    /// Adds a mapping between [`QueryId`] and [`HttpNetwork`] so that the server knows where to
    /// forward arriving data.
    /// # Errors
    /// if a query has been previously added
    pub fn add_query(
        &self,
        query_id: QueryId,
        network: HttpNetwork,
    ) -> Result<(), MpcHelperServerError> {
        self.message_send_map
            .insert_if_not_present(query_id, network)
    }

    /// Starts a new instance of MPC helper and binds it to a given target.
    /// Returns a socket it is listening to and the join handle of the web server running.
    pub async fn bind(&self, target: BindTarget) -> (SocketAddr, JoinHandle<()>) {
        let svc = self
            .router()
            .layer(TraceLayer::new_for_http().on_request(
                |request: &Request<Body>, _span: &Span| {
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

        (
            handle
                .listening()
                .await
                .expect("Failed to bind server to a port"),
            task_handle,
        )
    }
}

/// Returns `RustTlsConfig` instance configured with self-signed cert and key. Not intended to
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

/// [`MessageSendMap`] tests are limited right now due to the fact that they key, [`QueryId`], is
/// an empty struct, and so there can only ever be 1 entry in the map. When we fully define a
/// [`QueryId`], these tests can be expanded to handle more cases
#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;

    #[test]
    fn message_send_map_stores_sender() {
        let message_send_map = MessageSendMap::default();
        assert!(matches!(
            message_send_map.get(QueryId),
            Err(MpcHelperServerError::BadPathString(_))
        ));
        let network = HttpNetwork::new_without_clients(QueryId, None);
        message_send_map
            .insert_if_not_present(QueryId, network)
            .unwrap();
        assert!(message_send_map.get(QueryId).is_ok());
    }

    #[test]
    fn message_send_map_errors_on_double_add() {
        let message_send_map = MessageSendMap::default();
        message_send_map
            .insert_if_not_present(QueryId, HttpNetwork::new_without_clients(QueryId, None))
            .unwrap();
        assert!(matches!(
            message_send_map
                .insert_if_not_present(QueryId, HttpNetwork::new_without_clients(QueryId, None)),
            Err(MpcHelperServerError::SendError(_))
        ));
    }

    #[test]
    fn message_send_map_removes_sender() {
        let message_send_map = MessageSendMap::default();
        let network = HttpNetwork::new_without_clients(QueryId, None);
        message_send_map
            .insert_if_not_present(QueryId, network)
            .unwrap();
        assert!(message_send_map.get(QueryId).is_ok());
        message_send_map.remove(QueryId);
        assert!(matches!(
            message_send_map.get(QueryId),
            Err(MpcHelperServerError::BadPathString(_))
        ));
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod e2e_tests {
    use crate::{
        helpers::old_http::HttpNetwork,
        net::server::{handlers::EchoData, BindTarget, MessageSendMap, MpcHelperServer},
        protocol::QueryId,
        telemetry::metrics::{RequestProtocolVersion, REQUESTS_RECEIVED},
        test_fixture::metrics::MetricsHandle,
    };
    use hyper::{
        body,
        client::HttpConnector,
        header::{HeaderName, HeaderValue},
        http::uri::Scheme,
        Body, Request, Response, StatusCode, Version,
    };
    use hyper_tls::{native_tls::TlsConnector, HttpsConnector};
    use metrics_util::debugging::Snapshotter;
    use std::collections::HashMap;
    use std::str::FromStr;
    use tracing::Level;

    impl EchoData {
        pub fn to_request(&self, scheme: &Scheme) -> Request<Body> {
            let mut request = Request::builder();

            let uri = self.headers.get("host").expect("host header is missing");
            let query = self
                .query_args
                .iter()
                .map(|(arg, v)| format!("{arg}={v}"))
                .collect::<Vec<_>>()
                .join("&");

            for (name, val) in &self.headers {
                request.headers_mut().unwrap().insert(
                    HeaderName::from_str(name).unwrap(),
                    HeaderValue::from_str(val).unwrap(),
                );
            }

            let uri = format!("{scheme}://{uri}/echo?{query}");

            request.uri(uri).body(Body::empty()).unwrap()
        }

        pub async fn from_response(response: &mut Response<Body>) -> Self {
            let body_bytes = body::to_bytes(response.body_mut()).await.unwrap();

            serde_json::from_slice(&body_bytes).unwrap()
        }
    }

    #[tokio::test]
    async fn can_do_http() {
        let network = HttpNetwork::new_without_clients(QueryId, None);
        let message_send_map = MessageSendMap::filled(network);
        let server = MpcHelperServer::new(message_send_map);
        let (addr, _) = server
            .bind(BindTarget::Http("127.0.0.1:0".parse().unwrap()))
            .await;

        let expected = EchoData {
            query_args: HashMap::from([("foo".into(), "1".into()), ("bar".into(), "2".into())]),
            headers: HashMap::from([
                ("echo-header".into(), "echo".into()),
                ("host".into(), addr.to_string()),
            ]),
        };

        let client = hyper::Client::new();

        let mut response = client
            .request(expected.to_request(&Scheme::HTTP))
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, response.status());
        assert_eq!(expected, EchoData::from_response(&mut response).await);
    }

    #[tokio::test]
    async fn can_do_https() {
        let network = HttpNetwork::new_without_clients(QueryId, None);
        let message_send_map = MessageSendMap::filled(network);
        let server = MpcHelperServer::new(message_send_map);
        let config = crate::net::server::tls_config_from_self_signed_cert()
            .await
            .unwrap();
        let (addr, _) = server
            .bind(BindTarget::Https("127.0.0.1:0".parse().unwrap(), config))
            .await;

        let mut expected = EchoData::default();
        // self-signed cert CN is "localhost", therefore request uri must not use the ip address
        expected
            .headers
            .insert("host".into(), format!("localhost:{}", addr.port()));

        let conn = TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let mut http = HttpConnector::new();
        http.enforce_http(false);

        let https = HttpsConnector::<HttpConnector>::from((http, conn.into()));
        let client = hyper::Client::builder().build(https);

        let mut response = client
            .request(expected.to_request(&Scheme::HTTPS))
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, response.status());
        assert_eq!(expected, EchoData::from_response(&mut response).await);
    }

    /// Ensures that server tracks number of requests it received and emits a corresponding metric.
    /// In order for this test not to be flaky, we rely on tokio::test macro to set up a
    /// new runtime per test (which it currently does) and set up metric recorders per thread (done
    /// by this test). It is also tricky to make it work in a multi-threaded environment - I haven't
    /// tested that, so better to stick with default behavior of tokio:test macro
    #[tokio::test]
    async fn requests_received_metric() {
        let handle = MetricsHandle::new(Level::INFO);

        let network = HttpNetwork::new_without_clients(QueryId, None);
        let message_send_map = MessageSendMap::filled(network);
        let server = MpcHelperServer::new(message_send_map);

        let (addr, _) = server
            .bind(BindTarget::Http("127.0.0.1:0".parse().unwrap()))
            .await;
        let client = hyper::Client::new();
        let mut echo_data = EchoData::default();
        echo_data.headers.insert("host".into(), addr.to_string());

        let snapshot = Snapshotter::current_thread_snapshot();
        assert!(snapshot.is_none());

        let request_count = 10;
        for _ in 0..request_count {
            let response = client
                .request(echo_data.to_request(&Scheme::HTTP))
                .await
                .unwrap();
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
        let network = HttpNetwork::new_without_clients(QueryId, None);
        let message_send_map = MessageSendMap::filled(network);
        let server = MpcHelperServer::new(message_send_map);

        let (addr, _) = server
            .bind(BindTarget::Http("127.0.0.1:0".parse().unwrap()))
            .await;
        let mut echo_data = EchoData::default();
        let client = hyper::Client::new();
        echo_data.headers.insert("host".into(), addr.to_string());

        // make HTTP/1.1 request
        let response = client
            .request(echo_data.to_request(&Scheme::HTTP))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // make HTTP/2 request
        let client = hyper::Client::builder().http2_only(true).build_http();
        let response = client
            .request(echo_data.to_request(&Scheme::HTTP))
            .await
            .unwrap();
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
