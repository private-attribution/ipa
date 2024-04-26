use std::{
    collections::HashMap,
    future::Future,
    io,
    io::BufRead,
    pin::Pin,
    task::{ready, Context, Poll},
};

use axum::http::uri::{self, Parts, Scheme};
use futures::{Stream, StreamExt};
use hyper::{
    body, client::HttpConnector, header::HeaderName, http::HeaderValue, Body, Client, Request,
    Response, StatusCode, Uri,
};
use hyper_rustls::{ConfigBuilderExt, HttpsConnector, HttpsConnectorBuilder};
use pin_project::pin_project;
use rustls::RootCertStore;
use tracing::error;

use crate::{
    config::{
        ClientConfig, HyperClientConfigurator, NetworkConfig, OwnedCertificate, OwnedPrivateKey,
        PeerConfig,
    },
    helpers::{
        query::{PrepareQuery, QueryConfig, QueryInput},
        HelperIdentity,
    },
    net::{http_serde, server::HTTP_CLIENT_ID_HEADER, setup_crypto_provider, Error},
    protocol::{step::Gate, QueryId},
};

#[derive(Default)]
pub enum ClientIdentity {
    /// Claim the specified helper identity without any additional authentication.
    ///
    /// This is only supported for HTTP clients.
    Helper(HelperIdentity),

    /// Authenticate with an X.509 certificate or a certificate chain.
    ///
    /// This is only supported for HTTPS clients.
    Certificate((Vec<OwnedCertificate>, OwnedPrivateKey)),

    /// Do not authenticate nor claim a helper identity.
    #[default]
    None,
}

impl ClientIdentity {
    /// Authenticates clients with an X.509 certificate using the provided certificate and private
    /// key. Certificate must be in PEM format, private key encoding must be [`PKCS8`].
    ///
    /// [`PKCS8`]: https://datatracker.ietf.org/doc/html/rfc5958
    ///
    /// ## Errors
    /// If either cert or private key is not the required format.
    ///
    /// ## Panics
    /// If either cert or private key byte slice is empty.
    pub fn from_pkcs8(
        cert_read: &mut dyn BufRead,
        private_key_read: &mut dyn BufRead,
    ) -> Result<Self, io::Error> {
        Ok(Self::Certificate(
            crate::net::parse_certificate_and_private_key_bytes(cert_read, private_key_read)?,
        ))
    }

    /// Rust-tls-types crate intentionally does not implement Clone on private key types in order
    /// to minimize the exposure of private key data in memory. Since `ClientBuilder` API requires
    /// to own a private key, and we need to create 3 with the same config, we provide Clone
    /// capabilities via this method to `ClientIdentity`.
    #[must_use]
    pub fn clone_with_key(&self) -> ClientIdentity {
        match self {
            Self::Certificate((c, pk)) => Self::Certificate((c.clone(), pk.clone_key())),
            Self::Helper(h) => Self::Helper(*h),
            Self::None => Self::None,
        }
    }
}

/// Wrapper around Hyper's [future](hyper::client::ResponseFuture) interface that keeps around
/// request endpoint for nicer error messages if request fails.
#[pin_project]
pub struct ResponseFuture<'a> {
    authority: &'a uri::Authority,
    #[pin]
    inner: hyper::client::ResponseFuture,
}

/// Similar to [fut](ResponseFuture), wraps the response and keeps the URI authority for better
/// error messages that show where error is originated from
pub struct ResponseFromEndpoint<'a> {
    authority: &'a uri::Authority,
    inner: Response<Body>,
}

impl<'a> ResponseFromEndpoint<'a> {
    pub fn endpoint(&self) -> String {
        self.authority.to_string()
    }

    pub fn status(&self) -> StatusCode {
        self.inner.status()
    }

    pub fn into_body(self) -> Body {
        self.inner.into_body()
    }

    pub fn into_parts(self) -> (&'a uri::Authority, Body) {
        (self.authority, self.inner.into_body())
    }
}

impl<'a> Future for ResponseFuture<'a> {
    type Output = Result<ResponseFromEndpoint<'a>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match ready!(this.inner.poll(cx)) {
            Ok(resp) => Poll::Ready(Ok(ResponseFromEndpoint {
                authority: this.authority,
                inner: resp,
            })),
            Err(e) => Poll::Ready(Err(Error::ConnectError {
                dest: this.authority.to_string(),
                inner: e,
            })),
        }
    }
}

/// TODO: we need a client that can be used by any system that is not aware of the internals
///       of the helper network. That means that create query and send inputs API need to be
///       separated from prepare/step data etc.
/// TODO: It probably isn't necessary to always use `[MpcHelperClient; 3]`. Instead, a single
///       client can be configured to talk to all three helpers.
#[derive(Debug, Clone)]
pub struct MpcHelperClient {
    client: Client<HttpsConnector<HttpConnector>, Body>,
    scheme: uri::Scheme,
    authority: uri::Authority,
    auth_header: Option<(HeaderName, HeaderValue)>,
}

impl MpcHelperClient {
    /// Create a set of clients for the MPC helpers in the supplied helper network configuration.
    ///
    /// This function returns a set of three clients, which may be used to talk to each of the
    /// helpers.
    ///
    /// `identity` configures whether and how the client will authenticate to the server. It is for
    /// the helper making the calls, so the same one is used for all three of the clients.
    /// Authentication is not required when calling the report collector APIs.
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn from_conf(conf: &NetworkConfig, identity: &ClientIdentity) -> [MpcHelperClient; 3] {
        conf.peers()
            .iter()
            .map(|peer_conf| Self::new(&conf.client, peer_conf.clone(), identity.clone_with_key()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    /// Create a new client with the given configuration
    ///
    /// `identity`, if present, configures whether and how the client will authenticate to the server
    /// (e.g. an X.509 certificate).
    ///
    /// # Panics
    /// If some aspect of the configuration is not valid.
    #[must_use]
    pub fn new(
        client_config: &ClientConfig,
        peer_config: PeerConfig,
        identity: ClientIdentity,
    ) -> Self {
        setup_crypto_provider();
        let (connector, auth_header) = if peer_config.url.scheme() == Some(&Scheme::HTTP) {
            // This connector works for both http and https. A regular HttpConnector would suffice,
            // but would make the type of `self.client` variable.
            let auth_header = match identity {
                ClientIdentity::Certificate(_) => {
                    error!("certificate identity ignored for HTTP client");
                    None
                }
                ClientIdentity::Helper(id) => Some((HTTP_CLIENT_ID_HEADER.clone(), id.into())),
                ClientIdentity::None => None,
            };
            (
                HttpsConnectorBuilder::new()
                    .with_native_roots()
                    .expect("Error creating client with Rustls, native roots should be available.")
                    .https_or_http()
                    .enable_http2()
                    .wrap_connector(make_http_connector()),
                auth_header,
            )
        } else {
            let builder = rustls::ClientConfig::builder();
            let client_config = if let Some(certificate) = peer_config.certificate {
                let cert_store = {
                    let mut store = RootCertStore::empty();
                    store
                        .add(certificate)
                        .expect("Error adding Certificate, should be a valid Trust Anchor.");
                    store
                };

                let builder = builder.with_root_certificates(cert_store);
                match identity {
                    ClientIdentity::Certificate((cert_chain, pk)) => builder
                        .with_client_auth_cert(cert_chain, pk)
                        .expect("Can setup client authentication with certificate"),
                    ClientIdentity::Helper(_) => {
                        error!("header-passed identity ignored for HTTPS client");
                        builder.with_no_client_auth()
                    }
                    ClientIdentity::None => builder.with_no_client_auth(),
                }
            } else {
                builder.with_native_roots().unwrap().with_no_client_auth()
            };
            // `enforce_http` must be false to request HTTPS URLs. This is done automatically by
            // `HttpsConnector::new()`, but not by `HttpsConnector::from()`.
            let mut http = make_http_connector();
            http.enforce_http(false);
            (
                HttpsConnectorBuilder::new()
                    .with_tls_config(client_config)
                    .https_only()
                    .enable_http2()
                    .wrap_connector(http),
                None,
            )
        };
        Self::new_internal(peer_config.url, connector, auth_header, client_config)
    }

    #[must_use]
    fn new_internal<C: HyperClientConfigurator>(
        addr: Uri,
        connector: HttpsConnector<HttpConnector>,
        auth_header: Option<(HeaderName, HeaderValue)>,
        conf: &C,
    ) -> Self {
        let client = conf.configure(&mut Client::builder()).build(connector);
        let Parts {
            scheme: Some(scheme),
            authority: Some(authority),
            ..
        } = addr.into_parts()
        else {
            panic!("peer URL must have a scheme and authority");
        };
        Self {
            client,
            scheme,
            authority,
            auth_header,
        }
    }

    pub fn request(&self, mut req: Request<Body>) -> ResponseFuture<'_> {
        if let Some((k, v)) = self.auth_header.clone() {
            req.headers_mut().insert(k, v);
        }
        ResponseFuture {
            authority: &self.authority,
            inner: self.client.request(req),
        }
    }

    /// Responds with whatever input is passed to it
    /// # Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    pub async fn echo(&self, s: &str) -> Result<String, Error> {
        const FOO: &str = "foo";

        let req =
            http_serde::echo::Request::new(HashMap::from([(FOO.into(), s.into())]), HashMap::new());
        let req = req.try_into_http_request(self.scheme.clone(), self.authority.clone())?;
        let resp = self.request(req).await?;
        let status = resp.status();
        if status.is_success() {
            let result = hyper::body::to_bytes(resp.into_body()).await?;
            let http_serde::echo::Request {
                mut query_params, ..
            } = serde_json::from_slice(&result)?;
            // It is potentially confusing to synthesize a 500 error here, but
            // it doesn't seem worth creating an error variant just for this.
            query_params.remove(FOO).ok_or(Error::FailedHttpRequest {
                dest: self.authority.to_string(),
                status: StatusCode::INTERNAL_SERVER_ERROR,
                reason: "did not receive mirrored echo response".into(),
            })
        } else {
            Err(Error::from_failed_resp(resp).await)
        }
    }

    /// Helper to read a possible error response to a request that returns nothing on success
    ///
    /// # Errors
    /// If there was an error reading the response body or if the request itself failed.
    pub async fn resp_ok(resp: ResponseFromEndpoint<'_>) -> Result<(), Error> {
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(Error::from_failed_resp(resp).await)
        }
    }

    /// Intended to be called externally, by the report collector. Informs the MPC ring that
    /// the external party wants to start a new query.
    /// # Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    pub async fn create_query(&self, data: QueryConfig) -> Result<QueryId, Error> {
        let req = http_serde::query::create::Request::new(data);
        let req = req.try_into_http_request(self.scheme.clone(), self.authority.clone())?;
        let resp = self.request(req).await?;
        if resp.status().is_success() {
            let body_bytes = body::to_bytes(resp.into_body()).await?;
            let http_serde::query::create::ResponseBody { query_id } =
                serde_json::from_slice(&body_bytes)?;
            Ok(query_id)
        } else {
            Err(Error::from_failed_resp(resp).await)
        }
    }

    /// Used to communicate from one helper to another. Specifically, the helper that receives a
    /// "create query" from an external party must communicate the intent to start a query to the
    /// other helpers, which this prepare query does.
    /// # Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    pub async fn prepare_query(&self, data: PrepareQuery) -> Result<(), Error> {
        let req = http_serde::query::prepare::Request::new(data);
        let req = req.try_into_http_request(self.scheme.clone(), self.authority.clone())?;
        let resp = self.request(req).await?;
        Self::resp_ok(resp).await
    }

    /// Intended to be called externally, e.g. by the report collector. After the report collector
    /// calls "create query", it must then send the data for the query to each of the clients. This
    /// query input contains the data intended for a helper.
    /// # Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    pub async fn query_input(&self, data: QueryInput) -> Result<(), Error> {
        let req = http_serde::query::input::Request::new(data);
        let req = req.try_into_http_request(self.scheme.clone(), self.authority.clone())?;
        let resp = self.request(req).await?;
        Self::resp_ok(resp).await
    }

    /// Sends a batch of messages associated with a query's step to another helper. Messages are a
    /// contiguous block of records. Also includes [`crate::protocol::RecordId`] information and
    /// [`crate::helpers::network::ChannelId`].
    /// # Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    /// # Panics
    /// If messages size > max u32 (unlikely)
    pub fn step<S: Stream<Item = Vec<u8>> + Send + 'static>(
        &self,
        query_id: QueryId,
        gate: &Gate,
        data: S,
    ) -> Result<ResponseFuture, Error> {
        let body = hyper::Body::wrap_stream::<_, _, Error>(data.map(Ok));
        let req = http_serde::query::step::Request::new(query_id, gate.clone(), body);
        let req = req.try_into_http_request(self.scheme.clone(), self.authority.clone())?;
        Ok(self.request(req))
    }

    /// Retrieve the status of a query.
    ///
    /// ## Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    #[cfg(any(all(test, not(feature = "shuttle")), feature = "cli"))]
    pub async fn query_status(
        &self,
        query_id: QueryId,
    ) -> Result<crate::query::QueryStatus, Error> {
        let req = http_serde::query::status::Request::new(query_id);
        let req = req.try_into_http_request(self.scheme.clone(), self.authority.clone())?;

        let resp = self.request(req).await?;
        if resp.status().is_success() {
            let body_bytes = body::to_bytes(resp.into_body()).await?;
            let http_serde::query::status::ResponseBody { status } =
                serde_json::from_slice(&body_bytes)?;
            Ok(status)
        } else {
            Err(Error::from_failed_resp(resp).await)
        }
    }

    /// Wait for completion of the query and pull the results of this query. This is a blocking
    /// API so it is not supposed to be used outside of CLI context.
    ///
    /// ## Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    #[cfg(any(all(test, not(feature = "shuttle")), feature = "cli"))]
    pub async fn query_results(&self, query_id: QueryId) -> Result<body::Bytes, Error> {
        let req = http_serde::query::results::Request::new(query_id);
        let req = req.try_into_http_request(self.scheme.clone(), self.authority.clone())?;

        let resp = self.request(req).await?;
        if resp.status().is_success() {
            Ok(body::to_bytes(resp.into_body()).await?)
        } else {
            Err(Error::from_failed_resp(resp).await)
        }
    }
}

fn make_http_connector() -> HttpConnector {
    let mut connector = HttpConnector::new();
    // IPA uses HTTP2 and it is sensitive to those delays especially in high-latency network
    // configurations.
    connector.set_nodelay(true);

    connector
}

#[cfg(all(test, web_test))]
pub(crate) mod tests {
    use std::{
        fmt::Debug,
        future::{ready, Future},
        iter::zip,
        task::Poll,
    };

    use futures::stream::{once, poll_immediate};

    use super::*;
    use crate::{
        ff::{FieldType, Fp31},
        helpers::{
            make_owned_handler, query::QueryType::TestMultiply, BytesStream, HelperResponse,
            RequestHandler, RoleAssignment, Transport, MESSAGE_PAYLOAD_SIZE_BYTES,
        },
        net::test::TestServer,
        protocol::step::StepNarrow,
        query::ProtocolResult,
        secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
        sync::Arc,
    };

    #[tokio::test]
    async fn untrusted_certificate() {
        const ECHO_DATA: &str = "asdf";

        let TestServer { addr, .. } = TestServer::default().await;

        let peer_config = PeerConfig {
            url: format!("https://localhost:{}", addr.port())
                .parse()
                .unwrap(),
            certificate: None,
            hpke_config: None,
        };
        let client =
            MpcHelperClient::new(&ClientConfig::default(), peer_config, ClientIdentity::None);

        // The server's self-signed test cert is not in the system truststore, and we didn't supply
        // it in the client config, so the connection should fail with a certificate error.
        let res = client.echo(ECHO_DATA).await;
        assert!(matches!(res, Err(Error::ConnectError { inner: e, .. }) if e.is_connect()));
    }

    /// tests that a query command runs as expected. Since query commands require the server to
    /// actively respond to a client request, the test must handle both ends of the request
    /// simultaneously. That means taking the client behavior (`clientf`) and the server behavior
    /// (`serverf`), and executing them simultaneously (via a `join!`). Finally, return the results
    /// of `clientf` for final checks.
    ///
    /// Also tests that the same functionality works for both `http` and `https` and all supported
    /// HTTP versions (HTTP 1.1 and HTTP 2 at the moment) . In order to ensure
    /// this, the return type of `clientf` must be `Eq + Debug` so that the results can be compared.
    async fn test_query_command<ClientOut, ClientFut, ClientF, HandlerF>(
        clientf: ClientF,
        server_handler: HandlerF,
    ) -> ClientOut
    where
        ClientOut: Eq + Debug,
        ClientFut: Future<Output = ClientOut>,
        ClientF: Fn(MpcHelperClient) -> ClientFut,
        HandlerF: Fn() -> Arc<dyn RequestHandler<Identity = HelperIdentity>>,
    {
        let mut results = Vec::with_capacity(4);
        for (use_https, use_http1) in zip([true, false], [true, false]) {
            let mut test_server_builder = TestServer::builder();
            if !use_https {
                test_server_builder = test_server_builder.disable_https();
            }

            if use_http1 {
                test_server_builder = test_server_builder.use_http1();
            }

            let test_server = test_server_builder
                .with_request_handler(server_handler())
                .build()
                .await;

            results.push(clientf(test_server.client).await);
        }

        assert!(results.windows(2).all(|slice| slice[0] == slice[1]));

        results.pop().unwrap()
    }

    #[tokio::test]
    async fn echo() {
        let expected_output = "asdf";

        let output = test_query_command(
            |client| async move { client.echo(expected_output).await.unwrap() },
            || {
                make_owned_handler(move |addr, _| async move {
                    panic!("unexpected call: {addr:?}");
                })
            },
        )
        .await;
        assert_eq!(expected_output, &output);
    }

    #[tokio::test]
    async fn create() {
        let expected_query_id = QueryId;
        let expected_query_config = QueryConfig::new(TestMultiply, FieldType::Fp31, 1).unwrap();

        let handler = || {
            make_owned_handler(move |addr, _| async move {
                let query_config = addr.into::<QueryConfig>().unwrap();
                assert_eq!(query_config, expected_query_config);

                Ok(HelperResponse::from(PrepareQuery {
                    query_id: expected_query_id,
                    config: query_config,
                    roles: RoleAssignment::new(HelperIdentity::make_three()),
                }))
            })
        };
        let query_id = test_query_command(
            |client| async move { client.create_query(expected_query_config).await.unwrap() },
            handler,
        )
        .await;
        assert_eq!(query_id, expected_query_id);
    }

    #[tokio::test]
    async fn prepare() {
        let config = QueryConfig::new(TestMultiply, FieldType::Fp31, 1).unwrap();
        let handler = move || {
            make_owned_handler(move |addr, _| async move {
                let input = PrepareQuery {
                    query_id: QueryId,
                    config,
                    roles: RoleAssignment::new(HelperIdentity::make_three()),
                };
                let prepare_query = addr.into::<PrepareQuery>().unwrap();
                assert_eq!(prepare_query, input);

                Ok(HelperResponse::ok())
            })
        };

        test_query_command(
            |client| {
                let req = PrepareQuery {
                    query_id: QueryId,
                    config,
                    roles: RoleAssignment::new(HelperIdentity::make_three()),
                };
                async move { client.prepare_query(req).await.unwrap() }
            },
            handler,
        )
        .await;
    }

    #[tokio::test]
    async fn input() {
        let expected_query_id = QueryId;
        let expected_input = &[8u8; 25];
        let handler = move || {
            make_owned_handler(move |addr, data| async move {
                assert_eq!(addr.query_id, Some(expected_query_id));
                assert_eq!(data.to_vec().await, expected_input);

                Ok(HelperResponse::ok())
            })
        };
        test_query_command(
            |client| async move {
                let data = QueryInput {
                    query_id: expected_query_id,
                    input_stream: expected_input.to_vec().into(),
                };
                client.query_input(data).await.unwrap();
            },
            handler,
        )
        .await;
    }

    #[tokio::test]
    async fn step() {
        let TestServer {
            client, transport, ..
        } = TestServer::builder().build().await;
        let expected_query_id = QueryId;
        let expected_step = Gate::default().narrow("test-step");
        let expected_payload = vec![7u8; MESSAGE_PAYLOAD_SIZE_BYTES];

        let resp = client
            .step(
                expected_query_id,
                &expected_step,
                once(ready(expected_payload.clone())),
            )
            .unwrap()
            .await
            .unwrap();

        MpcHelperClient::resp_ok(resp).await.unwrap();

        let mut stream = Arc::clone(&transport)
            .receive(HelperIdentity::ONE, (QueryId, expected_step.clone()))
            .into_bytes_stream();

        assert_eq!(
            poll_immediate(&mut stream).next().await,
            Some(Poll::Ready(expected_payload))
        );
    }

    #[tokio::test]
    async fn results() {
        let expected_results = [
            Fp31::try_from(1u128).unwrap(),
            Fp31::try_from(2u128).unwrap(),
        ];
        let expected_query_id = QueryId;
        let handler = move || {
            make_owned_handler(move |addr, _| async move {
                let results: Box<dyn ProtocolResult> = Box::new(
                    [Replicated::from((expected_results[0], expected_results[1]))].to_vec(),
                );
                assert_eq!(addr.query_id, Some(expected_query_id));
                Ok(HelperResponse::from(results))
            })
        };
        let results = test_query_command(
            |client| async move { client.query_results(expected_query_id).await.unwrap() },
            handler,
        )
        .await;
        assert_eq!(
            results.to_vec(),
            [Replicated::from((expected_results[0], expected_results[1]))]
                .to_vec()
                .to_bytes()
        );
    }
}
