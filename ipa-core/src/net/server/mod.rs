mod config;
mod handlers;

use std::{
    borrow::Cow,
    io,
    marker::PhantomData,
    net::{Ipv4Addr, SocketAddr, TcpListener},
    ops::Deref,
    task::{Context, Poll},
};

use ::tokio::{
    fs,
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use axum::{
    Router,
    http::HeaderValue,
    response::{IntoResponse, Response},
    routing::IntoMakeService,
};
use axum_server::{
    Handle, Server,
    accept::Accept,
    service::SendService,
    tls_rustls::{RustlsAcceptor, RustlsConfig},
};
use futures::{
    FutureExt,
    future::{BoxFuture, Either, Ready, ready},
};
use hyper::{Request, body::Incoming};
use ipa_metrics::counter;
use rustls::{RootCertStore, server::WebPkiClientVerifier};
use tokio_rustls::server::TlsStream;
use tower::{Service, layer::layer_fn};
use tower_http::trace::TraceLayer;
use tracing::{Span, error};

use super::{HttpTransport, Shard, transport::MpcHttpTransport};
use crate::{
    config::{
        NetworkConfig, OwnedCertificate, OwnedPrivateKey, PeerConfig, ServerConfig, TlsConfig,
    },
    error::BoxError,
    executor::{IpaJoinHandle, IpaRuntime},
    helpers::TransportIdentity,
    net::{
        CRYPTO_PROVIDER, ConnectionFlavor, Error, Helper, parse_certificate_and_private_key_bytes,
        server::config::HttpServerConfig,
    },
    sync::Arc,
    telemetry::metrics::{REQUESTS_RECEIVED, web::RequestProtocolVersion},
};

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
/// `MpcHelperServer` handles requests from peer helpers, shards within the same helper and
/// external clients.
///
/// The Transport Restriction generic is used to make the server aware whether it should offer a
/// HTTP API for shards or for other Helpers. External clients can reach out to both APIs to push
/// the input data among other things.
pub struct IpaHttpServer<F: ConnectionFlavor> {
    config: ServerConfig,
    network_config: NetworkConfig<F>,
    router: Router,
}

impl IpaHttpServer<Helper> {
    #[must_use]
    pub fn new_mpc(
        transport: Arc<HttpTransport<Helper>>,
        config: ServerConfig,
        network_config: NetworkConfig<Helper>,
    ) -> Self {
        let router = handlers::mpc_router(MpcHttpTransport {
            inner_transport: transport,
        });
        IpaHttpServer {
            config,
            network_config,
            router,
        }
    }
}

impl IpaHttpServer<Shard> {
    #[must_use]
    pub fn new_shards(
        transport: Arc<HttpTransport<Shard>>,
        config: ServerConfig,
        network_config: NetworkConfig<Shard>,
    ) -> Self {
        let router = handlers::shard_router(transport);
        IpaHttpServer {
            config,
            network_config,
            router,
        }
    }
}

impl<F: ConnectionFlavor> IpaHttpServer<F> {
    #[cfg(all(test, unit_test))]
    pub(crate) async fn handle_req(
        &self,
        req: hyper::Request<axum::body::Body>,
    ) -> axum::response::Response {
        use tower::ServiceExt;
        self.router.clone().oneshot(req).await.unwrap()
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
    /// If the server TLS configuration is not valid, or if the match key encryption key
    /// configuration is invalid. (No match key encryption is okay for now, but if there is a key
    /// configured, it must be valid.)
    pub async fn start_on<T: TracingSpanMaker>(
        &self,
        runtime: &IpaRuntime,
        listener: Option<TcpListener>,
        tracing: T,
    ) -> (SocketAddr, IpaJoinHandle<()>) {
        // This should probably come from the server config.
        // Note that listening on 0.0.0.0 requires accepting a MacOS security
        // warning on each test run.
        #[cfg(test)]
        const BIND_ADDRESS: Ipv4Addr = Ipv4Addr::LOCALHOST;
        #[cfg(not(test))]
        const BIND_ADDRESS: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

        let svc = self.router.clone().layer(
            TraceLayer::new_for_http()
                .make_span_with(move |_request: &hyper::Request<_>| tracing.make_span())
                .on_request(|request: &hyper::Request<_>, _: &Span| {
                    counter!(RequestProtocolVersion::from(request.version()).as_str(), 1);
                    counter!(REQUESTS_RECEIVED, 1);
                }),
        );
        let handle = Handle::new();

        let task_handle = match (self.config.disable_https, listener) {
            (true, Some(listener)) => {
                let svc = svc
                    .layer(layer_fn(SetClientIdentityFromHeader::<_, F>::new))
                    .into_make_service();
                spawn_server(
                    runtime,
                    axum_server::from_tcp(listener),
                    handle.clone(),
                    svc,
                )
                .await
            }
            (true, None) => {
                let addr = SocketAddr::new(BIND_ADDRESS.into(), self.config.port.unwrap_or(0));
                let svc = svc
                    .layer(layer_fn(SetClientIdentityFromHeader::<_, F>::new))
                    .into_make_service();
                spawn_server(runtime, axum_server::bind(addr), handle.clone(), svc).await
            }
            (false, Some(listener)) => {
                let rustls_config = rustls_config(&self.config, self.network_config.vec_peers())
                    .await
                    .expect("invalid TLS configuration");
                spawn_server(
                    runtime,
                    axum_server::from_tcp_rustls(listener, rustls_config).map(|a| {
                        ClientCertRecognizingAcceptor::new(a, self.network_config.clone())
                    }),
                    handle.clone(),
                    svc.into_make_service(),
                )
                .await
            }
            (false, None) => {
                let addr = SocketAddr::new(BIND_ADDRESS.into(), self.config.port.unwrap_or(0));
                let rustls_config = rustls_config(&self.config, self.network_config.vec_peers())
                    .await
                    .expect("invalid TLS configuration");
                spawn_server(
                    runtime,
                    axum_server::bind_rustls(addr, rustls_config).map(|a| {
                        ClientCertRecognizingAcceptor::new(a, self.network_config.clone())
                    }),
                    handle.clone(),
                    svc.into_make_service(),
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
}

/// Spawns a new server with the given configuration.
/// This function glues Tower, Axum, Hyper and Axum-Server together, hence the trait bounds.
#[allow(clippy::unused_async)]
async fn spawn_server<A>(
    runtime: &IpaRuntime,
    mut server: Server<A>,
    handle: Handle,
    svc: IntoMakeService<Router>,
) -> IpaJoinHandle<()>
where
    A: Accept<TcpStream, Router> + Clone + Send + Sync + 'static,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send,
    A::Service: SendService<Request<Incoming>> + Send + Service<Request<Incoming>>,
    A::Future: Send,
{
    runtime.spawn({
        async move {
            // Apply configuration
            HttpServerConfig::apply(&mut server.http_builder().http2());
            // Start serving
            server
                .handle(handle)
                .serve(svc)
                .await
                .expect("Failed to serve");
        }
    })
}

async fn certificate_and_key(
    config: &ServerConfig,
) -> Result<(Vec<OwnedCertificate>, OwnedPrivateKey), BoxError> {
    let (cert, key) = match &config.tls {
        None => return Err("missing TLS configuration".into()),
        Some(TlsConfig::Inline {
            certificate,
            private_key,
        }) => (
            Cow::Borrowed(certificate.as_bytes()),
            Cow::Borrowed(private_key.as_bytes()),
        ),
        Some(TlsConfig::File {
            certificate_file,
            private_key_file,
        }) => {
            let cert = fs::read(certificate_file).await?;
            let key = fs::read(private_key_file).await?;
            (Cow::Owned(cert), Cow::Owned(key))
        }
    };
    parse_certificate_and_private_key_bytes(&mut cert.as_ref(), &mut key.as_ref())
        .map_err(BoxError::from)
}

/// Create a `RustlsConfig` for the `ServerConfig`.
///
/// `RustlsConfig` is an axum type. The native rustls configuration is `rustls::ServerConfig`, which
/// we import as `RustlsServerConfig`. Since we have particular needs related to client
/// certificates, we build a native rustls config, and then convert it into the axum config type.
///
/// # Errors
/// If there is a problem with the TLS configuration.
async fn rustls_config(
    config: &ServerConfig,
    certs: Vec<PeerConfig>,
) -> Result<RustlsConfig, BoxError> {
    let (cert, key) = certificate_and_key(config).await?;

    let mut trusted_certs = RootCertStore::empty();
    for cert in certs.into_iter().filter_map(|peer| peer.certificate) {
        // Note that this uses `webpki::TrustAnchor::try_from_cert_der`, which *does not* validate
        // the certificate. That is not required for security, but might be desirable to flag
        // configuration errors.
        trusted_certs.add(cert)?;
    }
    let client_verifier = WebPkiClientVerifier::builder_with_provider(
        trusted_certs.into(),
        Arc::clone(&CRYPTO_PROVIDER),
    )
    .allow_unauthenticated()
    .build()
    .expect("Error building client verifier, should specify valid Trust Anchors");
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::clone(&CRYPTO_PROVIDER))
        .with_safe_default_protocol_versions()
        .expect("Default crypto provider should be valid")
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert, key)?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(RustlsConfig::from_config(Arc::new(config)))
}

/// Axum `Extension` indicating the authenticated remote identity, if any. This can be either a
/// Shard authenticating or another Helper.
//
/// Presence or absence of authentication is indicated by presence or absence of the extension. Even
/// at some inconvenience (e.g. `MaybeExtensionExt`), we avoid using `Option` within the extension,
/// to avoid possible confusion about how many times the return from `req.extensions().get()` must be
/// unwrapped to ensure valid authentication.
#[derive(Clone, Copy, Debug, PartialEq)]
struct ClientIdentity<I: TransportIdentity>(pub I);

impl<I: TransportIdentity> Deref for ClientIdentity<I> {
    type Target = I;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<I: TransportIdentity> TryFrom<&HeaderValue> for ClientIdentity<I> {
    type Error = Error;

    fn try_from(value: &HeaderValue) -> Result<Self, Self::Error> {
        let header_str = value.to_str()?;
        I::from_str(header_str)
            .map_err(|e| Error::InvalidHeader(Box::new(e)))
            .map(ClientIdentity)
    }
}

/// `Accept`or that sets an axum `Extension` indiciating the authenticated remote helper identity.
/// Validating the certificate is something that happens earlier at connection time, this just
/// provide identity to the inner server handlers.
#[derive(Clone)]
struct ClientCertRecognizingAcceptor<F: ConnectionFlavor> {
    inner: RustlsAcceptor,
    network_config: Arc<NetworkConfig<F>>,
}

impl<F: ConnectionFlavor> ClientCertRecognizingAcceptor<F> {
    fn new(inner: RustlsAcceptor, network_config: NetworkConfig<F>) -> Self {
        Self {
            inner,
            network_config: Arc::new(network_config),
        }
    }
}

impl<I, S, F> Accept<I, S> for ClientCertRecognizingAcceptor<F>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
    F: ConnectionFlavor,
{
    type Stream = TlsStream<I>;
    type Service = SetClientIdentityFromCertificate<S, F>;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acceptor = self.inner.clone();
        let network_config = Arc::clone(&self.network_config);

        Box::pin(async move {
            let (stream, service) = acceptor.accept(stream, service).await.map_err(|err| {
                error!("[ClientCertRecognizingAcceptor] Internal acceptor error: {err}");
                err
            })?;

            // The return from `identify_client` is an `Option<HelperIdentity>`.
            // No client identity will be associated with the connection if:
            //  * No certificate was supplied.
            //  * There was a problem interpreting the certificate. It is unlikely to see an invalid
            //    certificate here, because the certificate must have passed full verification at
            //    connection time. But it's possible the certificate subject is not something we
            //    recognize as a helper.
            let opt_cert = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(<[_]>::first);
            let option_id: Option<F::Identity> = network_config.identify_cert(opt_cert);
            let client_id = option_id.map(ClientIdentity);
            let service = SetClientIdentityFromCertificate {
                inner: service,
                id: client_id,
            };
            Ok((stream, service))
        })
    }
}

#[derive(Clone)]
struct SetClientIdentityFromCertificate<S, F: ConnectionFlavor> {
    inner: S,
    id: Option<ClientIdentity<F::Identity>>,
}

impl<B, F, S> Service<Request<B>> for SetClientIdentityFromCertificate<S, F>
where
    S: Service<Request<B>>,
    F: ConnectionFlavor,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        if let Some(id) = self.id {
            req.extensions_mut().insert(id);
        }
        self.inner.call(req)
    }
}

/// Service wrapper that gets a client helper identity from a header.
///
/// Since this allows a client to claim any identity, it is completely
/// insecure. It must only be used in contexts where that is acceptable.
#[derive(Clone)]
struct SetClientIdentityFromHeader<S, F: ConnectionFlavor> {
    inner: S,
    _restriction: PhantomData<F>,
}

impl<S, F: ConnectionFlavor> SetClientIdentityFromHeader<S, F> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            _restriction: PhantomData,
        }
    }
}

impl<B, S, F> Service<Request<B>> for SetClientIdentityFromHeader<S, F>
where
    S: Service<Request<B>, Response = Response>,
    F: ConnectionFlavor,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Either<S::Future, Ready<Result<Response, S::Error>>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        if let Some(header_value) = req.headers().get(F::identity_header()) {
            let id_result = ClientIdentity::<F::Identity>::try_from(header_value);
            match id_result {
                Ok(id) => req.extensions_mut().insert(id),
                Err(err) => return ready(Ok(err.into_response())).right_future(),
            };
        }
        self.inner.call(req).left_future()
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use axum::http::HeaderValue;

    use crate::{helpers::HelperIdentity, net::server::ClientIdentity};

    #[test]
    fn identify_from_header_happy_case() {
        let h = HeaderValue::from_static("A");
        let id = ClientIdentity::<HelperIdentity>::try_from(&h);
        assert_eq!(id.unwrap(), ClientIdentity(HelperIdentity::ONE));
    }

    #[test]
    #[should_panic = "The string H1 is an invalid Helper Identity"]
    fn identify_from_header_wrong_header() {
        let h = HeaderValue::from_static("H1");
        let id = ClientIdentity::<HelperIdentity>::try_from(&h);
        id.unwrap();
    }
}

#[cfg(all(test, unit_test))]
mod e2e_tests {
    use std::collections::HashMap;

    use bytes::Buf;
    use http_body_util::BodyExt;
    use hyper::{StatusCode, Version, http::uri};
    use hyper_rustls::HttpsConnector;
    use hyper_util::{
        client::legacy::{
            Client,
            connect::{Connect, HttpConnector},
        },
        rt::{TokioExecutor, TokioTimer},
    };
    use rustls::{
        client::danger::{ServerCertVerified, ServerCertVerifier},
        pki_types::ServerName,
    };
    use rustls_pki_types::CertificateDer;
    use tracing::Level;

    use super::*;
    use crate::{
        net::{http_serde, test::TestServer},
        test_fixture::metrics::MetricsHandle,
    };

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
    ) -> hyper::Request<axum::body::Body> {
        expected
            .clone()
            .try_into_http_request(scheme, uri::Authority::try_from(authority).unwrap())
            .unwrap()
    }

    fn create_client_with_connector<C>(connector: C) -> Client<C, axum::body::Body>
    where
        C: Connect + Clone,
    {
        Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .build(connector)
    }

    fn create_client() -> Client<HttpConnector, axum::body::Body> {
        create_client_with_connector(HttpConnector::new())
    }

    #[tokio::test]
    async fn can_do_http() {
        // server
        let TestServer { addr, .. } = TestServer::builder().disable_https().build().await;

        let client = create_client();

        // request
        let expected = expected_req(addr.to_string());

        let req = http_req(&expected, uri::Scheme::HTTP, addr.to_string());
        let mut resp = client.request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.body_mut().collect().await.unwrap().aggregate();
        let resp_body: http_serde::echo::Request = serde_json::from_reader(body.reader()).unwrap();
        assert_eq!(expected, resp_body);
    }

    #[derive(Debug)]
    struct NoVerify;

    impl ServerCertVerifier for NoVerify {
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            ]
        }

        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls_pki_types::UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
    }

    #[tokio::test]
    async fn can_do_https() {
        let TestServer { addr, .. } = TestServer::builder().build().await;

        // self-signed cert CN is "localhost", therefore request authority must not use the ip address
        let authority = format!("localhost:{}", addr.port());

        // https client
        let config = rustls::ClientConfig::builder_with_provider(Arc::clone(&CRYPTO_PROVIDER))
            .with_safe_default_protocol_versions()
            .expect("Tests server should have working Crypto Provider")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        let mut http = HttpConnector::new();
        http.enforce_http(false);

        let https = HttpsConnector::<HttpConnector>::from((http, Arc::new(config)));
        let client = create_client_with_connector(https);

        // request
        let expected = expected_req(authority.clone());
        let req = http_req(&expected, uri::Scheme::HTTPS, authority);
        let resp = client.request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().aggregate();
        let resp_body: http_serde::echo::Request = serde_json::from_reader(body.reader()).unwrap();
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

        let client = create_client();

        // request
        let expected = expected_req(addr.to_string());

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
        let client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .build_http();
        let req = http_req(&expected, uri::Scheme::HTTP, addr.to_string());
        let response = client.request(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // make HTTP/2 request
        let client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .http2_only(true)
            .build_http();
        let req = http_req(&expected, uri::Scheme::HTTP, addr.to_string());
        let response = client.request(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        assert_eq!(
            Some(1),
            handle.get_counter_value(RequestProtocolVersion::from(Version::HTTP_11).as_str())
        );
        assert_eq!(
            Some(1),
            handle.get_counter_value(RequestProtocolVersion::from(Version::HTTP_2).as_str())
        );
        assert_eq!(
            None,
            handle.get_counter_value(RequestProtocolVersion::from(Version::HTTP_3).as_str())
        );
    }

    #[tokio::test]
    async fn http2_is_default() {
        let handle = MetricsHandle::new(Level::INFO);

        // server
        let TestServer { addr, client, .. } = TestServer::builder()
            // HTTP2 is disabled by default for HTTP traffic, so this verifies
            // our client is configured to enable it.
            // See https://github.com/private-attribution/ipa/issues/650 for motivation why
            // HTTP2 is required
            .disable_https()
            .with_metrics(handle.clone())
            .build()
            .await;

        let expected = expected_req(addr.to_string());
        let req = http_req(&expected, uri::Scheme::HTTP, addr.to_string());
        let response = client.request(req).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        assert_eq!(
            Some(1),
            handle.get_counter_value(RequestProtocolVersion::from(Version::HTTP_2).as_str())
        );
    }
}
