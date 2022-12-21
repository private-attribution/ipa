mod error;
mod handlers;

pub use error::Error;

use crate::{
    helpers::transport::TransportCommand,
    protocol::QueryId,
    sync::{Arc, Mutex},
    task::JoinHandle,
    telemetry::metrics::{RequestProtocolVersion, REQUESTS_RECEIVED},
};
use axum::Router;
use axum_server::{tls_rustls::RustlsConfig, Handle};
use hyper::{Body, Request};
use metrics::increment_counter;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::mpsc;
use tower_http::trace::TraceLayer;
use tracing::Span;

/// MPC helper supports HTTP and HTTPS protocols. Only the latter is suitable for production,
/// http mode may be useful to debug network communication on dev machines
pub enum BindTarget {
    Http(SocketAddr),
    Https(SocketAddr, RustlsConfig),
}

/// Contains all of the state needed to start the MPC server.
pub struct MpcHelperServer {
    transport_sender: mpsc::Sender<TransportCommand>,
    ongoing_queries: Arc<Mutex<HashMap<QueryId, mpsc::Sender<TransportCommand>>>>,
}

impl MpcHelperServer {
    pub fn new(
        transport_sender: mpsc::Sender<TransportCommand>,
        ongoing_queries: Arc<Mutex<HashMap<QueryId, mpsc::Sender<TransportCommand>>>>,
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
