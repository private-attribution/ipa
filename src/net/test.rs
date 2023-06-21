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
    config::{
        ClientConfig, HpkeClientConfig, HpkeServerConfig, NetworkConfig, PeerConfig, ServerConfig,
        TlsConfig,
    },
    helpers::{HelperIdentity, TransportCallbacks},
    hpke::{Deserializable as _, IpaPublicKey},
    net::{ClientIdentity, HttpTransport, MpcHelperClient, MpcHelperServer},
    sync::Arc,
    test_fixture::metrics::MetricsHandle,
};
use once_cell::sync::Lazy;
use std::{
    array,
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

// TODO: move these standalone functions into a new funcion `TestConfigBuilder::server_config`.
fn get_dummy_matchkey_encryption_info(matchkey_encryption: bool) -> Option<HpkeServerConfig> {
    if matchkey_encryption {
        Some(HpkeServerConfig::Inline {
            public_key: TEST_HPKE_PUBLIC_KEY.to_owned(),
            private_key: TEST_HPKE_PRIVATE_KEY.to_owned(),
        })
    } else {
        None
    }
}

#[must_use]
fn server_config_insecure_http(port: u16, matchkey_encryption: bool) -> ServerConfig {
    ServerConfig {
        port: Some(port),
        disable_https: true,
        tls: None,
        hpke_config: get_dummy_matchkey_encryption_info(matchkey_encryption),
    }
}

#[must_use]
pub fn server_config_https(
    id: HelperIdentity,
    port: u16,
    matchkey_encryption: bool,
) -> ServerConfig {
    let (certificate, private_key) = get_test_certificate_and_key(id);
    ServerConfig {
        port: Some(port),
        disable_https: false,
        tls: Some(TlsConfig::Inline {
            certificate: String::from_utf8(certificate.to_owned()).unwrap(),
            private_key: String::from_utf8(private_key.to_owned()).unwrap(),
        }),
        hpke_config: get_dummy_matchkey_encryption_info(matchkey_encryption),
    }
}

#[derive(Default)]
pub struct TestConfigBuilder {
    ports: Option<[u16; 3]>,
    disable_https: bool,
    use_http1: bool,
    disable_matchkey_encryption: bool,
}

impl TestConfigBuilder {
    #[must_use]
    pub fn with_http_and_default_test_ports() -> Self {
        Self {
            ports: Some(DEFAULT_TEST_PORTS),
            disable_https: true,
            use_http1: false,
            disable_matchkey_encryption: false,
        }
    }

    #[must_use]
    pub fn with_open_ports() -> Self {
        Self {
            ports: None,
            disable_https: false,
            use_http1: false,
            disable_matchkey_encryption: false,
        }
    }

    #[must_use]
    pub fn with_disable_https_option(mut self, value: bool) -> Self {
        self.disable_https = value;
        self
    }

    #[must_use]
    pub fn with_use_http1_option(mut self, value: bool) -> Self {
        self.use_http1 = value;
        self
    }

    #[allow(dead_code)]
    #[must_use]
    // TODO(richaj) Add tests for checking the handling of this. At present the code to decrypt does not exist.
    pub fn disable_matchkey_encryption(mut self) -> Self {
        self.disable_matchkey_encryption = true;
        self
    }

    #[must_use]
    pub fn build(self) -> TestConfig {
        let mut sockets = None;
        let ports = self.ports.unwrap_or_else(|| {
            let socks = array::from_fn(|_| TcpListener::bind("localhost:0").unwrap());
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
                hpke_config: if self.disable_matchkey_encryption {
                    None
                } else {
                    Some(HpkeClientConfig::new(
                        IpaPublicKey::from_bytes(
                            &hex::decode(TEST_HPKE_PUBLIC_KEY.trim()).unwrap(),
                        )
                        .unwrap(),
                    ))
                },
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let network = NetworkConfig {
            peers,
            client: self
                .use_http1
                .then(ClientConfig::use_http1)
                .unwrap_or_default(),
        };
        let servers = if self.disable_https {
            ports.map(|ports| server_config_insecure_http(ports, !self.disable_matchkey_encryption))
        } else {
            HelperIdentity::make_three()
                .map(|id| server_config_https(id, ports[id], !self.disable_matchkey_encryption))
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
    use_http1: bool,
    disable_matchkey_encryption: bool,
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

    #[allow(dead_code)]
    #[must_use]
    // TODO(richaj) Add tests for checking the handling of this. At present the code to decrypt does not exist.
    pub fn disable_matchkey_encryption(mut self) -> Self {
        self.disable_matchkey_encryption = true;
        self
    }

    #[cfg(all(test, not(feature = "shuttle"), feature = "real-world-infra"))]
    pub fn use_http1(mut self) -> Self {
        self.use_http1 = true;
        self
    }

    pub async fn build(self) -> TestServer {
        let identity = if self.disable_https {
            ClientIdentity::Helper(HelperIdentity::ONE)
        } else {
            get_test_identity(HelperIdentity::ONE)
        };
        let test_config = TestConfig::builder()
            .with_disable_https_option(self.disable_https)
            .with_use_http1_option(self.use_http1)
            // TODO: add disble_matchkey here
            .build();
        let TestConfig {
            network: network_config,
            servers: [server_config, _, _],
            sockets: Some([server_socket, _, _]),
            ..
        } = test_config else {
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
        let client = MpcHelperClient::new(&network_config.client, h1_peer_config, identity);
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
    (TEST_CERTS[id], TEST_KEYS[id])
}

#[must_use]
pub fn get_test_identity(id: HelperIdentity) -> ClientIdentity {
    let (certificate, private_key) = get_test_certificate_and_key(id);
    ClientIdentity::from_pks8(certificate, private_key).unwrap()
}

pub const TEST_CERTS: [&[u8]; 3] = [
    b"\
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
    b"\
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
    b"\
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
    TEST_CERTS.map(|mut pem| {
        rustls_pemfile::certs(&mut pem)
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
    })
});

pub const TEST_KEYS: [&[u8]; 3] = [
    b"\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSgj+YneEAzry+Tc6
dPeYP2chY5GtaXAl0vp5rxx8ccqhRANCAASbWRKgUuv42qnGwP26btId4yQ7A32e
5xVz7aSnfysEl1BcyftjbitKYZ+V7RyoVkYyv3JfvKJo+Uj2F7dscbFR
-----END PRIVATE KEY-----
",
    b"\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgB1nJigUsvqfOv9Zr
TNczUB6PexVrfUqmmqLC2uE5KZyhRANCAATj6piXMn3sedHSXvlzVJt9wSHbrhXF
KbSMVpfYjvuxPuyewHVRdrjP4M9y2lMSxoJqjzF/a+Gun9mD52thraTr
-----END PRIVATE KEY-----
",
    b"\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgn46qbscTVwdDs5sO
IyJbB/BrsRFSMBvLsUkh30dLdFyhRANCAATBOYXVQSeJ+ZDbja5BbNmChkPRIcP5
yV8EGPwurXSVtO3V2WHGFicoOuS5mEWAQJdgBHxlR+nn/EFOMN2JI7HV
-----END PRIVATE KEY-----
",
];

// Yes, these strings have trailing newlines. Things that consume them
// should strip whitespace.
const TEST_HPKE_PUBLIC_KEY: &str = "\
0ef21c2f73e6fac215ea8ec24d39d4b77836d09b1cf9aeb2257ddd181d7e663d
";

const TEST_HPKE_PRIVATE_KEY: &str = "\
a0778c3e9960576cbef4312a3b7ca34137880fd588c11047bd8b6a8b70b5a151
";
