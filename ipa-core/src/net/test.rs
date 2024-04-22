//! Utilities to generate configurations for unit tests.
//!
//! The convention for unit tests is that H1 is the server, H2 is the client, and H3 is not used
//! other than to write `NetworkConfig`. It is possible that this convention is not universally
//! respected.
//!
//! There is also some test setup for the case of three intercommunicating HTTP helpers in
//! `net::transport::tests`.

#![allow(clippy::missing_panics_doc)]
use std::{
    array,
    net::{SocketAddr, TcpListener},
};

use once_cell::sync::Lazy;
use rustls_pki_types::CertificateDer;
use tokio::task::JoinHandle;

use crate::{
    config::{
        ClientConfig, HpkeClientConfig, HpkeServerConfig, NetworkConfig, PeerConfig, ServerConfig,
        TlsConfig,
    },
    helpers::{HandlerBox, HelperIdentity, RequestHandler},
    hpke::{Deserializable as _, IpaPublicKey},
    net::{ClientIdentity, HttpTransport, MpcHelperClient, MpcHelperServer},
    sync::Arc,
    test_fixture::metrics::MetricsHandle,
};

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
                certificate: cert,
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

pub struct TestServer {
    pub addr: SocketAddr,
    pub handle: JoinHandle<()>,
    pub transport: Arc<HttpTransport>,
    pub server: MpcHelperServer,
    pub client: MpcHelperClient,
    pub request_handler: Option<Arc<dyn RequestHandler<Identity = HelperIdentity>>>,
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
    handler: Option<Arc<dyn RequestHandler<Identity = HelperIdentity>>>,
    metrics: Option<MetricsHandle>,
    disable_https: bool,
    use_http1: bool,
    disable_matchkey_encryption: bool,
}

impl TestServerBuilder {
    #[must_use]
    pub fn with_request_handler(
        mut self,
        handler: Arc<dyn RequestHandler<Identity = HelperIdentity>>,
    ) -> Self {
        self.handler = Some(handler);
        self
    }

    #[cfg(all(test, unit_test))]
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

    #[cfg(all(test, web_test))]
    #[must_use]
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
        } = test_config
        else {
            panic!("TestConfig should have allocated ports");
        };
        let clients = MpcHelperClient::from_conf(&network_config, &identity.clone_with_key());
        let handler = self.handler.as_ref().map(HandlerBox::owning_ref);
        let (transport, server) = HttpTransport::new(
            HelperIdentity::ONE,
            server_config,
            network_config.clone(),
            clients,
            handler,
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
            request_handler: self.handler,
        }
    }
}

fn get_test_certificate_and_key(id: HelperIdentity) -> (&'static [u8], &'static [u8]) {
    (TEST_CERTS[id], TEST_KEYS[id])
}

#[must_use]
pub fn get_test_identity(id: HelperIdentity) -> ClientIdentity {
    let (mut certificate, mut private_key) = get_test_certificate_and_key(id);
    ClientIdentity::from_pkcs8(&mut certificate, &mut private_key).unwrap()
}

pub const TEST_CERTS: [&[u8]; 3] = [
    b"\
-----BEGIN CERTIFICATE-----
MIIBZjCCAQ2gAwIBAgIIGGCAUnB4cZcwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJ
bG9jYWxob3N0MCAXDTIzMDgxNTE3MDEzM1oYDzIwNzMwODAyMTcwMTMzWjAUMRIw
EAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQulPXT
7xgX8ujzmgRHojfPAx7udp+4rXIwreV2CpvsqHJfjF+tqhPYI9VVJwKXpCEyWMyo
PcCnjX7t22nJt7Zuo0cwRTAUBgNVHREEDTALgglsb2NhbGhvc3QwDgYDVR0PAQH/
BAQDAgKkMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAKBggqhkjOPQQD
AgNHADBEAiAM9p5IUpI0/7vcCNZUebOvXogBKP8XOQ2MzLGq+hD/aQIgU7FXX6BO
MTmpcAH905PiJnhKrEJyGESyfv0D8jGZJXw=
-----END CERTIFICATE-----
",
    b"\
-----BEGIN CERTIFICATE-----
MIIBZjCCAQ2gAwIBAgIILilUFFCeLaowCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJ
bG9jYWxob3N0MCAXDTIzMDgxNTE3MDEzM1oYDzIwNzMwODAyMTcwMTMzWjAUMRIw
EAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQkeRc+
xcqwKtwc7KXfiz0qfRX1roD+ESxMP7GWIuJinNoJCKOUw2pVqJTHp86sk6BHTD3E
ULlYJ2fjKR/ogsZPo0cwRTAUBgNVHREEDTALgglsb2NhbGhvc3QwDgYDVR0PAQH/
BAQDAgKkMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAKBggqhkjOPQQD
AgNHADBEAiBuUib76qjK9aDHd7nD5LWE3V4WeBhwDktaDED5qmqHUgIgXCBJn8Fh
fqkn1QdTcGapzuMJqmhMzYUPeRJ4Vr1h7HA=
-----END CERTIFICATE-----
",
    b"\
-----BEGIN CERTIFICATE-----
MIIBZjCCAQ2gAwIBAgIIbYdpxPgluuUwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJ
bG9jYWxob3N0MCAXDTIzMDgxNTE3MDEzM1oYDzIwNzMwODAyMTcwMTMzWjAUMRIw
EAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASEORA/
IDvqRGiJpddoyocRa+9HEG2B6P8vfTTV28Ph7n9YBgJodGd29Kt7Dy2IdCjy7PsO
ik5KGZ4Ee+a+juKko0cwRTAUBgNVHREEDTALgglsb2NhbGhvc3QwDgYDVR0PAQH/
BAQDAgKkMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAKBggqhkjOPQQD
AgNHADBEAiB+K2yadiLIDR7ZvDpyMIXP70gL3CXp7JmVmh8ygFtbjQIgU16wnFBy
jn+NXYPeKEWnkCcVKjFED6MevGnOgrJylgY=
-----END CERTIFICATE-----
",
];

pub static TEST_CERTS_DER: Lazy<[CertificateDer; 3]> = Lazy::new(|| {
    TEST_CERTS.map(|mut pem| rustls_pemfile::certs(&mut pem).flatten().next().unwrap())
});

pub const TEST_KEYS: [&[u8]; 3] = [
    b"\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgHmPeGcv6Dy9QWPHD
ZU7CA+ium1zctVC4HZnrhFlfdiGhRANCAAQulPXT7xgX8ujzmgRHojfPAx7udp+4
rXIwreV2CpvsqHJfjF+tqhPYI9VVJwKXpCEyWMyoPcCnjX7t22nJt7Zu
-----END PRIVATE KEY-----
",
    b"\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvoE0RVtf/0DuE5qt
AimoTcGcGA7dRgq70Ycp0VX2qTqhRANCAAQkeRc+xcqwKtwc7KXfiz0qfRX1roD+
ESxMP7GWIuJinNoJCKOUw2pVqJTHp86sk6BHTD3EULlYJ2fjKR/ogsZP
-----END PRIVATE KEY-----
",
    b"\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgDfOsXGbO9T6e9mPb
u9BeVKo7j/DyX4j3XcqrOYnIwOOhRANCAASEORA/IDvqRGiJpddoyocRa+9HEG2B
6P8vfTTV28Ph7n9YBgJodGd29Kt7Dy2IdCjy7PsOik5KGZ4Ee+a+juKk
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
