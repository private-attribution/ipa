use crate::{
    config::NetworkConfig,
    helpers::{HelperIdentity, TransportCallbacks},
    net::{BindTarget, HttpTransport, MpcHelperClient, MpcHelperServer},
    sync::Arc,
    test_fixture::metrics::MetricsHandle,
};
use axum::{
    body::{Body, Bytes},
    extract::{BodyStream, FromRequest, RequestParts},
    http::Request,
};
#[cfg(any(test, feature = "self-signed-certs"))]
use axum_server::tls_rustls::RustlsConfig;
use futures::Stream;
use hyper::{
    client::HttpConnector,
    http::{uri::Scheme, Uri},
};
use hyper_tls::{native_tls::TlsConnector, HttpsConnector};
use once_cell::sync::Lazy;
use std::{error::Error as StdError, net::SocketAddr, ops::Deref};
use tokio::task::JoinHandle;

static DEFAULT_SERVER_URL: Lazy<Uri> = Lazy::new(|| "http://localhost:3000".parse().unwrap());

type HttpTransportCallbacks = TransportCallbacks<Arc<HttpTransport>>;

pub async fn body_stream(
    stream: Box<dyn Stream<Item = Result<Bytes, Box<dyn StdError + Send + Sync>>> + Send>,
) -> BodyStream {
    BodyStream::from_request(&mut RequestParts::new(
        Request::builder()
            .uri("/ignored")
            .body(Body::from(stream))
            .unwrap(),
    ))
    .await
    .unwrap()
}

pub struct TestServer {
    pub addr: SocketAddr,
    pub handle: JoinHandle<()>,
    pub transport: Arc<HttpTransport>,
    pub server: MpcHelperServer,
    pub client: MpcHelperClient,
}

impl TestServer {
    /// Build default set of test clients
    ///
    /// All three clients will be configured with the same default server URL, thus,
    /// at most one client will do anything useful.
    pub async fn default() -> TestServer {
        Self::builder().build().await
    }

    /// Return a test client builder
    pub fn builder() -> TestServerBuilder {
        TestServerBuilder::default()
    }
}

#[derive(Default)]
pub struct TestServerBuilder {
    callbacks: Option<HttpTransportCallbacks>,
    metrics: Option<MetricsHandle>,
    https: bool,
}

/// Construct an *insecure* HTTPS client for a test server.
///
/// The resulting client accepts invalid server certificates and is thus only suitable for test
/// usage.
fn https_client(addr: SocketAddr) -> MpcHelperClient {
    // requires custom client to use self signed certs
    let conn = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let https = HttpsConnector::<HttpConnector>::from((http, conn.into()));
    let uri = Uri::builder()
        .scheme(Scheme::HTTPS)
        .authority(format!("localhost:{}", addr.port()))
        .path_and_query("/")
        .build()
        .unwrap();
    MpcHelperClient::new_with_connector(uri, https)
}

impl TestServerBuilder {
    pub fn with_callbacks(mut self, callbacks: HttpTransportCallbacks) -> Self {
        self.callbacks = Some(callbacks);
        self
    }

    #[cfg(all(test, feature = "in-memory-infra"))] // only used in unit tests
    pub fn with_metrics(mut self, metrics: MetricsHandle) -> Self {
        self.metrics = Some(metrics);
        self
    }

    #[allow(dead_code)] // TODO: fix when TLS is enabled
    pub fn https(mut self) -> Self {
        self.https = true;
        self
    }

    pub async fn build(self) -> TestServer {
        let clients = TestClients::default();
        let (transport, server) = HttpTransport::new(
            HelperIdentity::ONE, // TODO: make this an argument?
            clients.into(),
            self.callbacks.unwrap_or_default(),
        );
        let bind_target = if self.https {
            let config = tls_config_from_self_signed_cert().await.unwrap();
            BindTarget::Https("127.0.0.1:0".parse().unwrap(), config)
        } else {
            BindTarget::Http("127.0.0.1:0".parse().unwrap())
        };
        let (addr, handle) = server.bind(bind_target, self.metrics).await;
        let client = if self.https {
            https_client(addr)
        } else {
            MpcHelperClient::with_str_addr(&format!("http://{addr}")).unwrap()
        };
        TestServer {
            addr,
            handle,
            transport,
            server,
            client,
        }
    }
}

pub struct TestClients(pub [MpcHelperClient; 3]);

impl Deref for TestClients {
    type Target = [MpcHelperClient; 3];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<TestClients> for [MpcHelperClient; 3] {
    fn from(value: TestClients) -> [MpcHelperClient; 3] {
        value.0
    }
}

impl TestClients {
    /// Build default set of test clients
    ///
    /// All three clients will be configured with the same default server URL, thus,
    /// at most one client will do anything useful.
    pub fn default() -> Self {
        Self::builder().build()
    }

    /// Return a test client builder
    pub fn builder() -> TestClientsBuilder {
        TestClientsBuilder::default()
    }
}

#[derive(Default)]
pub struct TestClientsBuilder {
    network_config: Option<NetworkConfig>,
}

impl TestClientsBuilder {
    pub fn with_network_config(mut self, network_config: NetworkConfig) -> Self {
        self.network_config = Some(network_config);
        self
    }

    pub fn build(self) -> TestClients {
        TestClients(match self.network_config {
            Some(config) => MpcHelperClient::from_conf(&config),
            None => [0, 1, 2].map(|_| MpcHelperClient::new(DEFAULT_SERVER_URL.clone())),
        })
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
