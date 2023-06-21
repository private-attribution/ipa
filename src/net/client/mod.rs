use crate::{
    config::{ClientConfig, HyperClientConfigurator, NetworkConfig, PeerConfig},
    helpers::{
        query::{PrepareQuery, QueryConfig, QueryInput},
        HelperIdentity,
    },
    net::{http_serde, server::HTTP_CLIENT_ID_HEADER, Error},
    protocol::{step::Gate, QueryId},
};
use axum::http::uri::{self, Parts, Scheme};
use futures::{Stream, StreamExt};
use hyper::{
    body,
    client::{HttpConnector, ResponseFuture},
    header::HeaderName,
    http::HeaderValue,
    Body, Client, Request, Response, StatusCode, Uri,
};
use hyper_rustls::{ConfigBuilderExt, HttpsConnector, HttpsConnectorBuilder};
use std::{
    collections::HashMap,
    io,
    io::{BufReader, Cursor},
    iter::repeat,
};
use tokio_rustls::{
    rustls,
    rustls::{Certificate, PrivateKey, RootCertStore},
};
use tracing::error;

#[derive(Clone, Default)]
pub enum ClientIdentity {
    /// Claim the specified helper identity without any additional authentication.
    ///
    /// This is only supported for HTTP clients.
    Helper(HelperIdentity),

    /// Authenticate with an X.509 certificate or a certificate chain.
    ///
    /// This is only supported for HTTPS clients.
    Certificate((Vec<Certificate>, PrivateKey)),

    /// Do not authenticate nor claim a helper identity.
    #[default]
    None,
}

impl ClientIdentity {
    /// Authenticates clients with an X.509 certificate using the provided certificate and private
    /// key. Certificate must be in DER format, private key encoding must be [`PKCS8`].
    ///
    /// [`PKCS8`]: https://datatracker.ietf.org/doc/html/rfc5958
    ///
    /// ## Errors
    /// If either cert or private key is not the required format.
    ///
    /// ## Panics
    /// If either cert or private key byte slice is empty.
    pub fn from_pks8(cert_bytes: &[u8], private_key_bytes: &[u8]) -> Result<Self, io::Error> {
        let mut certs_reader = BufReader::new(Cursor::new(cert_bytes));
        let mut pk_reader = BufReader::new(Cursor::new(private_key_bytes));

        let cert_chain = rustls_pemfile::certs(&mut certs_reader)?
            .into_iter()
            .map(Certificate)
            .collect();
        let pk = rustls_pemfile::pkcs8_private_keys(&mut pk_reader)?
            .pop()
            .expect("Non-empty byte slice is provided to parse a private key");

        Ok(Self::Certificate((cert_chain, PrivateKey(pk))))
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
    pub fn from_conf(conf: &NetworkConfig, identity: ClientIdentity) -> [MpcHelperClient; 3] {
        conf.peers()
            .iter()
            .zip(repeat(identity))
            .map(|(peer_conf, identity)| Self::new(&conf.client, peer_conf.clone(), identity))
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
        let (connector, auth_header) = if peer_config.url.scheme() == Some(&Scheme::HTTP) {
            // This connector works for both http and https. A regular HttpConnector would suffice,
            // but would make the type of `self.client` variable.
            let auth_header = match identity {
                ClientIdentity::Certificate(_) => {
                    error!("certificate identity ignored for HTTP client");
                    None
                }
                ClientIdentity::Helper(id) => Some((
                    HTTP_CLIENT_ID_HEADER.clone(),
                    id.try_into().expect("integer not ascii?"),
                )),
                ClientIdentity::None => None,
            };
            (
                HttpsConnectorBuilder::new()
                    .with_native_roots()
                    .https_or_http()
                    .enable_http2()
                    .wrap_connector(make_http_connector()),
                auth_header,
            )
        } else {
            let builder = rustls::ClientConfig::builder().with_safe_defaults();
            let client_config = if let Some(certificate) = peer_config.certificate {
                let cert_store = {
                    let mut store = RootCertStore::empty();
                    store.add(&certificate).unwrap();
                    store
                };

                let builder = builder.with_root_certificates(cert_store);
                match identity {
                    ClientIdentity::Certificate((cert_chain, pk)) => builder
                        .with_single_cert(cert_chain, pk)
                        .expect("Can setup client authentication with certificate"),
                    ClientIdentity::Helper(_) => {
                        error!("header-passed identity ignored for HTTPS client");
                        builder.with_no_client_auth()
                    }
                    ClientIdentity::None => builder.with_no_client_auth(),
                }
            } else {
                builder.with_native_roots().with_no_client_auth()
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
        } = addr.into_parts() else {
            panic!("peer URL must have a scheme and authority");
        };
        Self {
            client,
            scheme,
            authority,
            auth_header,
        }
    }

    pub fn request(&self, mut req: Request<Body>) -> ResponseFuture {
        if let Some((k, v)) = self.auth_header.clone() {
            req.headers_mut().insert(k, v);
        }
        self.client.request(req)
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
    pub async fn resp_ok(resp: Response<Body>) -> Result<(), Error> {
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

    /// Wait for completion of the query and pull the results of this query. This is a blocking
    /// API so it is not supposed to be used outside of CLI context.
    ///
    /// ## Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    /// # Panics
    /// if there is a problem reading the response body
    #[cfg(any(all(test, not(feature = "shuttle")), feature = "cli"))]
    pub async fn query_results(&self, query_id: QueryId) -> Result<body::Bytes, Error> {
        let req = http_serde::query::results::Request::new(query_id);
        let req = req.try_into_http_request(self.scheme.clone(), self.authority.clone())?;

        let resp = self.request(req).await?;
        if resp.status().is_success() {
            Ok(body::to_bytes(resp.into_body()).await.unwrap())
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

#[cfg(all(test, not(feature = "shuttle"), feature = "real-world-infra"))]
pub(crate) mod tests {
    use super::*;
    use crate::{
        ff::{FieldType, Fp31},
        helpers::{
            query::QueryType, BytesStream, RoleAssignment, Transport, TransportCallbacks,
            MESSAGE_PAYLOAD_SIZE_BYTES,
        },
        net::{test::TestServer, HttpTransport},
        protocol::step::StepNarrow,
        query::ProtocolResult,
        secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
        sync::Arc,
    };
    use futures::stream::{once, poll_immediate};
    use std::{
        fmt::Debug,
        future::{ready, Future},
        iter::zip,
        task::Poll,
    };

    // This is a kludgy way of working around `TransportCallbacks` not being `Clone`, so
    // that tests can run against both HTTP and HTTPS servers with one set.
    //
    // If the use grows beyond that, it's probably worth doing something more elegant, on the
    // TransportCallbacks type itself (references and lifetime parameters, dyn_clone, or make it a
    // trait and implement it on an `Arc` type).
    fn clone_callbacks<T: 'static>(
        cb: TransportCallbacks<T>,
    ) -> (TransportCallbacks<T>, TransportCallbacks<T>) {
        fn wrap<T: 'static>(inner: &Arc<TransportCallbacks<T>>) -> TransportCallbacks<T> {
            let ri = Arc::clone(inner);
            let pi = Arc::clone(inner);
            let qi = Arc::clone(inner);
            let ci = Arc::clone(inner);
            TransportCallbacks {
                receive_query: Box::new(move |t, req| (ri.receive_query)(t, req)),
                prepare_query: Box::new(move |t, req| (pi.prepare_query)(t, req)),
                query_input: Box::new(move |t, req| (qi.query_input)(t, req)),
                complete_query: Box::new(move |t, req| (ci.complete_query)(t, req)),
            }
        }

        let arc_cb = Arc::new(cb);
        (wrap(&arc_cb), wrap(&arc_cb))
    }

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
        assert!(matches!(res, Err(Error::HyperPassthrough(e)) if e.is_connect()));
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
    async fn test_query_command<ClientOut, ClientFut, ClientF>(
        clientf: ClientF,
        server_cb: TransportCallbacks<Arc<HttpTransport>>,
    ) -> ClientOut
    where
        ClientOut: Eq + Debug,
        ClientFut: Future<Output = ClientOut>,
        ClientF: Fn(MpcHelperClient) -> ClientFut,
    {
        let mut cb = server_cb;
        let mut results = Vec::with_capacity(4);
        for (use_https, use_http1) in zip([true, false], [true, false]) {
            let (cur, next) = clone_callbacks(cb);
            cb = next;

            let mut test_server_builder = TestServer::builder();
            if !use_https {
                test_server_builder = test_server_builder.disable_https();
            }

            if use_http1 {
                test_server_builder = test_server_builder.use_http1();
            }

            let TestServer {
                client: http_client,
                ..
            } = test_server_builder.with_callbacks(cur).build().await;

            results.push(clientf(http_client).await);
        }

        assert!(results.windows(2).all(|slice| slice[0] == slice[1]));

        results.pop().unwrap()
    }

    #[tokio::test]
    async fn echo() {
        let expected_output = "asdf";

        let output = test_query_command(
            |client| async move { client.echo(expected_output).await.unwrap() },
            TransportCallbacks::default(),
        )
        .await;
        assert_eq!(expected_output, &output);
    }

    #[tokio::test]
    async fn create() {
        let expected_query_id = QueryId;
        let expected_query_config = QueryConfig {
            field_type: FieldType::Fp31,
            query_type: QueryType::TestMultiply,
        };
        let cb = TransportCallbacks {
            receive_query: Box::new(move |_transport, query_config| {
                assert_eq!(query_config, expected_query_config);
                Box::pin(ready(Ok(expected_query_id)))
            }),
            ..Default::default()
        };
        let query_id = test_query_command(
            |client| async move { client.create_query(expected_query_config).await.unwrap() },
            cb,
        )
        .await;
        assert_eq!(query_id, expected_query_id);
    }

    #[tokio::test]
    async fn prepare() {
        let input = PrepareQuery {
            query_id: QueryId,
            config: QueryConfig {
                field_type: FieldType::Fp31,
                query_type: QueryType::TestMultiply,
            },
            roles: RoleAssignment::new(HelperIdentity::make_three()),
        };
        let expected_data = input.clone();
        let cb = TransportCallbacks {
            prepare_query: Box::new(move |_transport, prepare_query| {
                assert_eq!(prepare_query, expected_data);
                Box::pin(ready(Ok(())))
            }),
            ..Default::default()
        };
        test_query_command(
            |client| {
                let req = input.clone();
                async move { client.prepare_query(req).await.unwrap() }
            },
            cb,
        )
        .await;
    }

    #[tokio::test]
    async fn input() {
        let expected_query_id = QueryId;
        let expected_input = &[8u8; 25];
        let cb = TransportCallbacks {
            query_input: Box::new(move |_transport, query_input| {
                Box::pin(async move {
                    assert_eq!(query_input.query_id, expected_query_id);
                    assert_eq!(&query_input.input_stream.to_vec().await, expected_input);
                    Ok(())
                })
            }),
            ..Default::default()
        };
        test_query_command(
            |client| async move {
                let data = QueryInput {
                    query_id: expected_query_id,
                    input_stream: expected_input.to_vec().into(),
                };
                client.query_input(data).await.unwrap()
            },
            cb,
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

        let mut stream =
            Arc::clone(&transport).receive(HelperIdentity::ONE, (QueryId, expected_step.clone()));

        assert_eq!(
            poll_immediate(&mut stream).next().await,
            Some(Poll::Ready(expected_payload))
        );
    }

    #[tokio::test]
    async fn results() {
        let expected_results = Box::new(vec![Replicated::from((
            Fp31::try_from(1u128).unwrap(),
            Fp31::try_from(2u128).unwrap(),
        ))]);
        let expected_query_id = QueryId;
        let raw_results = expected_results.to_vec();
        let cb = TransportCallbacks {
            complete_query: Box::new(move |_transport, query_id| {
                let results: Box<dyn ProtocolResult> = Box::new(raw_results.clone());
                assert_eq!(query_id, expected_query_id);
                Box::pin(ready(Ok(results)))
            }),
            ..Default::default()
        };
        let results = test_query_command(
            |client| async move { client.query_results(expected_query_id).await.unwrap() },
            cb,
        )
        .await;
        assert_eq!(results.to_vec(), expected_results.into_bytes());
    }
}
