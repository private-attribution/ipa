//! Utilities to generate configurations for unit tests.
//!
//! The convention for unit tests is that H1 is the server, H2 is the client, and H3 is not used
//! other than to write `NetworkConfig`. It is possible that this convention is not universally
//! respected.
//!
//! There is also some test setup for the case of three intercommunicating HTTP helpers in
//! `net::transport::tests`.

#![allow(clippy::missing_panics_doc)]

use crate::{
    config::{NetworkConfig, PeerConfig, ServerConfig, TlsConfig},
    helpers::{HelperIdentity, TransportCallbacks},
    net::{ClientIdentity, HttpTransport, MpcHelperClient, MpcHelperServer},
    sync::Arc,
    test_fixture::metrics::MetricsHandle,
};
use axum::{
    body::{Body, Bytes},
    extract::{BodyStream, FromRequest, RequestParts},
    http::Request,
};
use futures::Stream;
use hyper_tls::native_tls::Identity;
use once_cell::sync::Lazy;
use std::{
    array,
    error::Error as StdError,
    net::{SocketAddr, TcpListener},
};
use tokio::task::JoinHandle;
use tokio_rustls::rustls::Certificate;

pub const DEFAULT_TEST_PORTS: [u16; 3] = [3000, 3001, 3002];

pub struct TestConfig {
    pub disable_https: bool,
    pub network: NetworkConfig,
    pub servers: [ServerConfig; 3],
    pub sockets: Option<[TcpListener; 3]>,
}

impl TestConfig {
    #[must_use]
    pub fn builder() -> TestConfigBuilder {
        TestConfigBuilder::default()
    }
}

impl Default for TestConfig {
    fn default() -> Self {
        Self::builder().build()
    }
}

#[must_use]
fn server_config_insecure_http(port: u16) -> ServerConfig {
    ServerConfig {
        port: Some(port),
        disable_https: true,
        tls: None,
    }
}

#[must_use]
pub fn server_config_https(id: HelperIdentity, port: u16) -> ServerConfig {
    let (certificate, private_key) = get_test_certificate_and_key(id);
    ServerConfig {
        port: Some(port),
        disable_https: false,
        tls: Some(TlsConfig::Inline {
            certificate: String::from_utf8(certificate.to_owned()).unwrap(),
            private_key: String::from_utf8(private_key.to_owned()).unwrap(),
        }),
    }
}

#[derive(Default)]
pub struct TestConfigBuilder {
    ports: Option<[u16; 3]>,
    disable_https: bool,
}

impl TestConfigBuilder {
    #[must_use]
    pub fn with_http_and_default_test_ports() -> Self {
        Self {
            ports: Some(DEFAULT_TEST_PORTS),
            disable_https: true,
        }
    }

    #[must_use]
    pub fn with_open_ports() -> Self {
        Self {
            ports: None,
            disable_https: false,
        }
    }

    #[must_use]
    pub fn with_disable_https_option(mut self, value: bool) -> Self {
        self.disable_https = value;
        self
    }

    #[must_use]
    pub fn build(self) -> TestConfig {
        let mut sockets = None;
        let ports = self.ports.unwrap_or_else(|| {
            let socks = array::from_fn(|_| TcpListener::bind("127.0.0.1:0").unwrap());
            let ports = socks
                .iter()
                .map(|sock| sock.local_addr().unwrap().port())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            sockets = Some(socks);
            ports
        });
        let (scheme, certs) = if self.disable_https {
            ("http", [None, None, None])
        } else {
            ("https", TEST_CERTS_DER.clone().map(Some))
        };
        let peers = certs
            .into_iter()
            .enumerate()
            .map(|(i, cert)| PeerConfig {
                url: format!("{scheme}://localhost:{}", ports[i])
                    .parse()
                    .unwrap(),
                certificate: cert.map(Certificate),
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let network = NetworkConfig { peers };
        let servers = if self.disable_https {
            ports.map(server_config_insecure_http)
        } else {
            HelperIdentity::make_three().map(|id| server_config_https(id, ports[id]))
        };
        TestConfig {
            network,
            servers,
            sockets,
            disable_https: self.disable_https,
        }
    }
}

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
    #[must_use]
    pub fn builder() -> TestServerBuilder {
        TestServerBuilder::default()
    }
}

#[derive(Default)]
pub struct TestServerBuilder {
    callbacks: Option<HttpTransportCallbacks>,
    metrics: Option<MetricsHandle>,
    disable_https: bool,
}

impl TestServerBuilder {
    #[must_use]
    pub fn with_callbacks(mut self, callbacks: HttpTransportCallbacks) -> Self {
        self.callbacks = Some(callbacks);
        self
    }

    #[cfg(all(test, feature = "in-memory-infra"))] // only used in unit tests
    #[must_use]
    pub fn with_metrics(mut self, metrics: MetricsHandle) -> Self {
        self.metrics = Some(metrics);
        self
    }

    #[must_use]
    pub fn disable_https(mut self) -> Self {
        self.disable_https = true;
        self
    }

    pub async fn build(self) -> TestServer {
        let identity = if self.disable_https {
            ClientIdentity::Helper(HelperIdentity::ONE)
        } else {
            get_test_identity(HelperIdentity::ONE)
        };
        let TestConfig {
            network: network_config,
            servers: [server_config, _, _],
            sockets: Some([server_socket, _, _]),
            ..
        } = TestConfig::builder().with_disable_https_option(self.disable_https).build() else {
            panic!("TestConfig should have allocated ports");
        };
        let clients = MpcHelperClient::from_conf(&network_config, identity.clone());
        let (transport, server) = HttpTransport::new(
            HelperIdentity::ONE,
            server_config,
            network_config.clone(),
            clients,
            self.callbacks.unwrap_or_default(),
        );
        let (addr, handle) = server.start_on(Some(server_socket), self.metrics).await;
        // Get the config for HelperIdentity::ONE
        let h1_peer_config = network_config.peers.into_iter().next().unwrap();
        // At some point it might be appropriate to return two clients here -- the first being
        // another helper and the second being a report collector. For now we use the same client
        // for both types of calls.
        let client = MpcHelperClient::new(h1_peer_config, identity);
        TestServer {
            addr,
            handle,
            transport,
            server,
            client,
        }
    }
}

fn get_test_certificate_and_key(id: HelperIdentity) -> (&'static [u8], &'static [u8]) {
    // TODO(640): to be removed when we standardize on rustls
    #[cfg(not(target_os = "macos"))]
    let key = TEST_KEYS[id];
    #[cfg(target_os = "macos")]
    let key = TEST_KEYS_MUNGED[id];
    (TEST_CERTS[id].as_bytes(), key.as_bytes())
}

#[must_use]
pub fn get_test_identity(id: HelperIdentity) -> ClientIdentity {
    let (certificate, private_key) = get_test_certificate_and_key(id);
    ClientIdentity::Certificate(Identity::from_pkcs8(certificate, private_key).unwrap())
}

pub const TEST_CERTS: [&str; 3] = [
    "\
-----BEGIN CERTIFICATE-----
MIIBZjCCAQugAwIBAgIIIw4wCKfWSPwwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJ
bG9jYWxob3N0MB4XDTIzMDUxNDIwNDQ0MloXDTIzMDgxMzIwNDQ0MlowFDESMBAG
A1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEm1kSoFLr
+NqpxsD9um7SHeMkOwN9nucVc+2kp38rBJdQXMn7Y24rSmGfle0cqFZGMr9yX7yi
aPlI9he3bHGxUaNHMEUwFAYDVR0RBA0wC4IJbG9jYWxob3N0MA4GA1UdDwEB/wQE
AwICpDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwCgYIKoZIzj0EAwID
SQAwRgIhAOyM9wLZFviaBJxofO1biI14hsfF83ZjmJ3ecfTt/HdfAiEAgzGzmJQC
T0I681GCNIl5G+81QhtxZU+L/wTFEDvZab8=
-----END CERTIFICATE-----
",
    "\
-----BEGIN CERTIFICATE-----
MIIBZTCCAQugAwIBAgIIALb+d1gYZ6wwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJ
bG9jYWxob3N0MB4XDTIzMDUxNDIwNDQ0MloXDTIzMDgxMzIwNDQ0MlowFDESMBAG
A1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4+qYlzJ9
7HnR0l75c1SbfcEh264VxSm0jFaX2I77sT7snsB1UXa4z+DPctpTEsaCao8xf2vh
rp/Zg+drYa2k66NHMEUwFAYDVR0RBA0wC4IJbG9jYWxob3N0MA4GA1UdDwEB/wQE
AwICpDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwCgYIKoZIzj0EAwID
SAAwRQIgAxmYy2xWLuT7Tj4mPN4o2dN6hUUrLgDoaB3ANKGn6HUCIQDWCWDEFYz6
axKi9RVXFKJRTl+2uDnvJDlByuu9eO7Zcw==
-----END CERTIFICATE-----
",
    "\
-----BEGIN CERTIFICATE-----
MIIBZjCCAQugAwIBAgIICNNqnceOGYowCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJ
bG9jYWxob3N0MB4XDTIzMDUxNDIwNDQ0MloXDTIzMDgxMzIwNDQ0MlowFDESMBAG
A1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwTmF1UEn
ifmQ242uQWzZgoZD0SHD+clfBBj8Lq10lbTt1dlhxhYnKDrkuZhFgECXYAR8ZUfp
5/xBTjDdiSOx1aNHMEUwFAYDVR0RBA0wC4IJbG9jYWxob3N0MA4GA1UdDwEB/wQE
AwICpDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwCgYIKoZIzj0EAwID
SQAwRgIhAI+C0EKy19WiQjm8WukTVDBQls48axbloGjtmGdCpQz2AiEAuZnRtQhq
ap/vPUI/erdbh9kBXcOaHSDVR3gCfhuPhyI=
-----END CERTIFICATE-----
",
];

pub static TEST_CERTS_DER: Lazy<[Vec<u8>; 3]> = Lazy::new(|| {
    TEST_CERTS.map(|pem| {
        rustls_pemfile::certs(&mut pem.as_bytes())
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
    })
});

pub const TEST_KEYS: [&str; 3] = [
    "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSgj+YneEAzry+Tc6
dPeYP2chY5GtaXAl0vp5rxx8ccqhRANCAASbWRKgUuv42qnGwP26btId4yQ7A32e
5xVz7aSnfysEl1BcyftjbitKYZ+V7RyoVkYyv3JfvKJo+Uj2F7dscbFR
-----END PRIVATE KEY-----
",
    "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgB1nJigUsvqfOv9Zr
TNczUB6PexVrfUqmmqLC2uE5KZyhRANCAATj6piXMn3sedHSXvlzVJt9wSHbrhXF
KbSMVpfYjvuxPuyewHVRdrjP4M9y2lMSxoJqjzF/a+Gun9mD52thraTr
-----END PRIVATE KEY-----
",
    "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgn46qbscTVwdDs5sO
IyJbB/BrsRFSMBvLsUkh30dLdFyhRANCAATBOYXVQSeJ+ZDbja5BbNmChkPRIcP5
yV8EGPwurXSVtO3V2WHGFicoOuS5mEWAQJdgBHxlR+nn/EFOMN2JI7HV
-----END PRIVATE KEY-----
",
];

// These keys are re-coded by the munge_private_key function in `src/bin/helper.rs`.
// TODO(640): to be removed when we standardize on rustls
#[cfg(target_os = "macos")]
pub const TEST_KEYS_MUNGED: [&str; 3] = [
    "\
-----BEGIN PRIVATE KEY-----
MHcCAQEEIEoI/mJ3hAM68vk3OnT3mD9nIWORrWlwJdL6ea8cfHHKoAoGCCqGSM49
AwEHoUQDQgAEm1kSoFLr+NqpxsD9um7SHeMkOwN9nucVc+2kp38rBJdQXMn7Y24r
SmGfle0cqFZGMr9yX7yiaPlI9he3bHGxUQ==
-----END PRIVATE KEY-----
",
    "\
-----BEGIN PRIVATE KEY-----
MHcCAQEEIAdZyYoFLL6nzr/Wa0zXM1Aej3sVa31KppqiwtrhOSmcoAoGCCqGSM49
AwEHoUQDQgAE4+qYlzJ97HnR0l75c1SbfcEh264VxSm0jFaX2I77sT7snsB1UXa4
z+DPctpTEsaCao8xf2vhrp/Zg+drYa2k6w==
-----END PRIVATE KEY-----
",
    "\
-----BEGIN PRIVATE KEY-----
MHcCAQEEIJ+Oqm7HE1cHQ7ObDiMiWwfwa7ERUjAby7FJId9HS3RcoAoGCCqGSM49
AwEHoUQDQgAEwTmF1UEnifmQ242uQWzZgoZD0SHD+clfBBj8Lq10lbTt1dlhxhYn
KDrkuZhFgECXYAR8ZUfp5/xBTjDdiSOx1Q==
-----END PRIVATE KEY-----
",
];
