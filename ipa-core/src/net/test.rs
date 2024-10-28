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
    collections::HashSet,
    net::{SocketAddr, TcpListener},
    ops::Index,
};

use once_cell::sync::Lazy;
use rustls_pki_types::CertificateDer;

use super::{transport::MpcHttpTransport, ConnectionFlavor, Shard};
use crate::{
    config::{
        ClientConfig, HpkeClientConfig, HpkeServerConfig, NetworkConfig, PeerConfig, ServerConfig,
        TlsConfig,
    },
    executor::{IpaJoinHandle, IpaRuntime},
    helpers::{HandlerBox, HelperIdentity, RequestHandler, TransportIdentity},
    hpke::{Deserializable as _, IpaPublicKey},
    net::{ClientIdentity, Helper, MpcHelperClient, MpcHelperServer},
    sharding::{ShardIndex, ShardedHelperIdentity},
    sync::Arc,
    test_fixture::metrics::MetricsHandle,
};

/// Simple struct to keep default port configuration organized.
#[derive(Clone)]
pub struct Ports {
    ring: [u16; 3],
    shards: [u16; 3],
}

/// A **single** ring with 3 hosts, each with a ring and sharding port.
pub const DEFAULT_TEST_PORTS: Ports = Ports {
    ring: [3000, 3001, 3002],
    shards: [6000, 6001, 6002],
};

/// Configuration of a server that can be reached via socket or port.
pub struct AddressableTestServer {
    pub id: ShardedHelperIdentity,
    /// Contains the ports
    pub config: ServerConfig,
    /// Sockets are created if no port was specified.
    pub socket: Option<TcpListener>,
}

/// Creates a new socket from the OS if no port is given.
fn create_port(optional_port: Option<u16>) -> (Option<TcpListener>, u16) {
    if let Some(port) = optional_port {
        (None, port)
    } else {
        let socket = TcpListener::bind("localhost:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        (Some(socket), port)
    }
}

impl AddressableTestServer {
    /// Creates a new Test Server with the given Id. If no port is given, one will be obtained from
    /// the OS.
    fn new(
        id: ShardedHelperIdentity,
        optional_port: Option<u16>,
        conf: &TestConfigBuilder,
    ) -> Self {
        let (socket, port) = create_port(optional_port);
        let config = if conf.disable_https {
            server_config_insecure_http(port, !conf.disable_matchkey_encryption)
        } else {
            server_config_https(id, port, !conf.disable_matchkey_encryption)
        };
        Self { id, config, socket }
    }
}

/// Either a single Ring on MPC connection or all of the shards in a Helper.
pub struct TestNetwork<F: ConnectionFlavor> {
    pub network: NetworkConfig<F>, // Contains Clients config
    pub servers: Vec<AddressableTestServer>,
}

impl<F: ConnectionFlavor> TestNetwork<F> {
    /// Helper function that creates [`PeerConfig`]
    fn create_peers(
        servers: &[AddressableTestServer],
        conf: &TestConfigBuilder,
    ) -> Vec<PeerConfig> {
        servers
            .iter()
            .map(|addr_server| {
                let port = addr_server
                    .config
                    .port
                    .expect("Port should have been defined already");
                let (scheme, certificate) = if conf.disable_https {
                    ("http", None)
                } else {
                    ("https", Some(TEST_CERTS_DER[addr_server.id].clone()))
                };
                let url = format!("{scheme}://localhost:{port}").parse().unwrap();
                let hpke_config = if conf.disable_matchkey_encryption {
                    None
                } else {
                    Some(HpkeClientConfig::new(
                        IpaPublicKey::from_bytes(
                            &hex::decode(TEST_HPKE_PUBLIC_KEY.trim()).unwrap(),
                        )
                        .unwrap(),
                    ))
                };
                PeerConfig {
                    url,
                    certificate,
                    hpke_config,
                }
            })
            .collect()
    }
}

impl TestNetwork<Shard> {
    #[must_use]
    /// Gets a ref to the first shard in this network.
    pub fn get_first_shard(&self) -> &AddressableTestServer {
        self.servers.first().unwrap()
    }

    /// Gets a mut ref to the first shard in this network.
    pub fn get_first_shard_mut(&mut self) -> &mut AddressableTestServer {
        self.servers.get_mut(0).unwrap()
    }
}

impl TestNetwork<Helper> {
    /// Creates 3 mpc test servers and creates a network.
    fn new_mpc(ix: ShardIndex, ports: Vec<Option<u16>>, conf: &TestConfigBuilder) -> Self {
        let servers: Vec<_> = HelperIdentity::make_three()
            .into_iter()
            .zip(ports)
            .map(|(id, p)| {
                let sid = ShardedHelperIdentity::new(id, ix);
                AddressableTestServer::new(sid, p, conf)
            })
            .collect();
        let peers = Self::create_peers(servers.as_slice(), conf);
        let client_config = conf.create_client_config();
        let network = NetworkConfig::<Helper>::new_mpc(peers, client_config);
        TestNetwork { network, servers }
    }
}

impl TestNetwork<Shard> {
    /// Creates all the shards for a helper and creates a network.
    fn new_shards(id: HelperIdentity, ports: Vec<Option<u16>>, conf: &TestConfigBuilder) -> Self {
        let servers: Vec<_> = (0..conf.shard_count)
            .map(ShardIndex)
            .zip(ports)
            .map(|(ix, p)| {
                let sid = ShardedHelperIdentity::new(id, ix);
                AddressableTestServer::new(sid, p, conf)
            })
            .collect();
        let peers = Self::create_peers(servers.as_slice(), conf);
        let client_config = conf.create_client_config();
        let network = NetworkConfig::<Shard>::new_shards(peers, client_config);
        TestNetwork { network, servers }
    }
}

// TODO: move these standalone functions into a new funcion `TestConfigBuilder::server_config`.
fn get_dummy_matchkey_encryption_info(matchkey_encryption: bool) -> Option<HpkeServerConfig> {
    if matchkey_encryption {
        Some(HpkeServerConfig::Inline {
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
fn server_config_https(
    id: ShardedHelperIdentity,
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

/// Uber container for test configuration. Provides access to a vec of MPC rings and 3 sharding
/// networks (one for each Helper)
pub struct TestConfig {
    pub disable_https: bool,
    pub rings: Vec<TestNetwork<Helper>>,
    pub shards: Vec<TestNetwork<Shard>>,
}

impl TestConfig {
    /// Gets a ref to the first ring in the network. This ring is important because it's the one
    /// that's reached out by the report collector on behalf of all the shards in the helper.
    #[must_use]
    pub fn leaders_ring(&self) -> &TestNetwork<Helper> {
        &self.rings[0]
    }

    /// Gets a ref to the entire shard network for a specific helper.
    #[must_use]
    pub fn get_shards_for_helper(&self, id: HelperIdentity) -> &TestNetwork<Shard> {
        self.shards.get(id.as_index()).unwrap()
    }

    /// Gets a mut ref to the entire shard network for a specific helper.
    pub fn get_shards_for_helper_mut(&mut self, id: HelperIdentity) -> &mut TestNetwork<Shard> {
        self.shards.get_mut(id.as_index()).unwrap()
    }

    /// Creates a new [`TestConfig`] using the provided configuration.
    fn new(conf: &TestConfigBuilder) -> Self {
        let rings = (0..conf.shard_count)
            .map(ShardIndex)
            .map(|s| {
                let ports = conf.get_ports_for_shard_index(s);
                TestNetwork::<Helper>::new_mpc(s, ports, conf)
            })
            .collect();
        let shards = HelperIdentity::make_three()
            .into_iter()
            .map(|id| {
                let ports = conf.get_ports_for_helper_identity(id);
                TestNetwork::<Shard>::new_shards(id, ports, conf)
            })
            .collect();
        Self {
            disable_https: conf.disable_https,
            rings,
            shards,
        }
    }
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

pub struct TestConfigBuilder {
    /// Can be None, meaning that free ports should be obtained from the operating system.
    /// One ring per shard in a helper (see [`shard_count`]). For each ring we need 3 shard
    /// (A `Vec<u16>`) and 3 mpc ports.
    ports_by_ring: Option<Vec<Ports>>,
    /// Describes the number of shards per helper. This is directly related to [`ports_by_ring`].
    shard_count: u32,
    disable_https: bool,
    use_http1: bool,
    disable_matchkey_encryption: bool,
}

impl Default for TestConfigBuilder {
    /// Non-sharded, HTTPS and get ports from OS.
    fn default() -> Self {
        Self {
            ports_by_ring: None,
            shard_count: 1,
            disable_https: false,
            use_http1: false,
            disable_matchkey_encryption: false,
        }
    }
}

impl TestConfigBuilder {
    #[must_use]
    pub fn with_http_and_default_test_ports() -> Self {
        Self {
            ports_by_ring: Some(vec![DEFAULT_TEST_PORTS]),
            shard_count: 1,
            disable_https: true,
            use_http1: false,
            disable_matchkey_encryption: false,
        }
    }

    #[must_use]
    pub fn with_disable_https_option(mut self, value: bool) -> Self {
        self.disable_https = value;
        self
    }

    /// Sets the ports the test network should use.
    /// # Panics
    /// If a duplicate port is given.
    #[must_use]
    pub fn with_ports_by_ring(mut self, value: Vec<Ports>) -> Self {
        self.shard_count = value.len().try_into().unwrap();
        let mut uniqueness_set = HashSet::new();
        for ps in &value {
            for p in ps.ring.iter().chain(ps.shards.iter()) {
                assert!(uniqueness_set.insert(p), "Found duplicate port {p}");
            }
        }
        self.ports_by_ring = Some(value);
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

    /// Creates a HTTP1 or HTTP2 client config.
    pub fn create_client_config(&self) -> ClientConfig {
        self.use_http1
            .then(ClientConfig::use_http1)
            .unwrap_or_default()
    }

    /// Get all the MPC ports in a ring specified by the shard index.
    fn get_ports_for_shard_index(&self, ix: ShardIndex) -> Vec<Option<u16>> {
        if let Some(ports_by_ring) = &self.ports_by_ring {
            let ports = ports_by_ring[ix.as_index()].clone();
            ports.ring.into_iter().map(Some).collect()
        } else {
            vec![None; 3]
        }
    }

    /// Get all the shard ports in a helper.
    fn get_ports_for_helper_identity(&self, id: HelperIdentity) -> Vec<Option<u16>> {
        if let Some(ports_by_ring) = &self.ports_by_ring {
            ports_by_ring
                .iter()
                .map(|r| r.shards[id.as_index()])
                .map(Some)
                .collect()
        } else {
            vec![None; self.shard_count.try_into().unwrap()]
        }
    }

    /// Creates a test network with shards.
    #[must_use]
    pub fn build(&self) -> TestConfig {
        TestConfig::new(self)
    }
}
pub struct TestServer {
    pub addr: SocketAddr,
    pub handle: IpaJoinHandle<()>,
    pub transport: MpcHttpTransport,
    pub server: MpcHelperServer<Helper>,
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
        let identities =
            ClientIdentities::new(self.disable_https, ShardedHelperIdentity::ONE_FIRST);
        let mut test_config = TestConfig::builder()
            .with_disable_https_option(self.disable_https)
            .with_use_http1_option(self.use_http1)
            // TODO: add disble_matchkey here
            .build();
        let leaders_ring = test_config.rings.pop().unwrap();
        let first_server = leaders_ring.servers.into_iter().next().unwrap();
        let clients = MpcHelperClient::from_conf(
            &IpaRuntime::current(),
            &leaders_ring.network,
            &identities.helper.clone_with_key(),
        );
        let handler = self.handler.as_ref().map(HandlerBox::owning_ref);
        let client = clients[0].clone();
        let (transport, server) = MpcHttpTransport::new(
            IpaRuntime::current(),
            HelperIdentity::ONE,
            first_server.config,
            leaders_ring.network.clone(),
            &clients,
            handler,
        );
        let (addr, handle) = server
            .start_on(&IpaRuntime::current(), first_server.socket, self.metrics)
            .await;
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

pub struct ClientIdentities {
    pub helper: ClientIdentity<Helper>,
    pub shard: ClientIdentity<Shard>,
}

impl ClientIdentities {
    #[must_use]
    pub fn new(disable_https: bool, id: ShardedHelperIdentity) -> Self {
        if disable_https {
            ClientIdentities {
                helper: ClientIdentity::Header(id.helper_identity),
                shard: ClientIdentity::Header(id.shard_index),
            }
        } else {
            get_client_test_identity(id)
        }
    }
}

impl<const S: usize> Index<ShardedHelperIdentity> for [&'static [u8]; S] {
    type Output = &'static [u8];

    fn index(&self, index: ShardedHelperIdentity) -> &Self::Output {
        let pos = index.as_index();
        self.get(pos)
            .unwrap_or_else(|| panic!("The computed index {pos} is outside of {S}"))
    }
}

impl<const S: usize> Index<ShardedHelperIdentity> for Lazy<[CertificateDer<'static>; S]> {
    type Output = CertificateDer<'static>;

    fn index(&self, index: ShardedHelperIdentity) -> &Self::Output {
        let pos = index.as_index();
        self.get(pos)
            .unwrap_or_else(|| panic!("The computed index {pos} is outside of {S}"))
    }
}

pub(super) fn get_test_certificate_and_key(
    id: ShardedHelperIdentity,
) -> (&'static [u8], &'static [u8]) {
    (TEST_CERTS[id], TEST_KEYS[id])
}

/// Creating a cert client identity. Using the same certificate for both shard and mpc.
#[must_use]
pub fn get_client_test_identity(id: ShardedHelperIdentity) -> ClientIdentities {
    let (mut certificate, mut private_key) = get_test_certificate_and_key(id);
    let (mut scertificate, mut sprivate_key) = get_test_certificate_and_key(id);
    ClientIdentities {
        helper: ClientIdentity::from_pkcs8(&mut certificate, &mut private_key).unwrap(),
        shard: ClientIdentity::from_pkcs8(&mut scertificate, &mut sprivate_key).unwrap(),
    }
}

const TEST_CERTS: [&[u8]; 6] = [
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
    b"
-----BEGIN CERTIFICATE-----
MIIBZDCCAQugAwIBAgIIFeKzq6ypfYgwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJ
bG9jYWxob3N0MB4XDTI0MTAwNjIyMTEzOFoXDTI1MDEwNTIyMTEzOFowFDESMBAG
A1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECKdJUHmm
Mmqtvhu4PpWwwZnu+LFjaE8Y9guDNIXN+O9kulFl1hLVMx6WLpoScrLYlvHrQvcq
/BTG24EOKAeaRqNHMEUwFAYDVR0RBA0wC4IJbG9jYWxob3N0MA4GA1UdDwEB/wQE
AwICpDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwCgYIKoZIzj0EAwID
RwAwRAIgBO2SBoLmPikfcovOFpjA8jpY+JuSybeISUKD2GAsXQICIEChXm7/UJ7p
86qXEVsjN2N1pyRd6rUNxLyCaV87ZmfS
-----END CERTIFICATE-----
",
    b"
-----BEGIN CERTIFICATE-----
MIIBZTCCAQugAwIBAgIIXTgB/bkN/aUwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJ
bG9jYWxob3N0MB4XDTI0MTAwNjIyMTIwM1oXDTI1MDEwNTIyMTIwM1owFDESMBAG
A1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyzSofZIX
XgLUKGumrN3SEXOMOAKXcl1VshTBzvyVwxxnD01WVLgS80/TELEltT8SMj1Cgu7I
tkDx3EVPjq4pOKNHMEUwFAYDVR0RBA0wC4IJbG9jYWxob3N0MA4GA1UdDwEB/wQE
AwICpDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwCgYIKoZIzj0EAwID
SAAwRQIhAN93g0zfB/4VyhNOaY1uCb4af4qMxcz1wp0yZ7HKAyWqAiBVPgv4X7aR
JMepVZwIWJrVhnxdcmzOuONoeLZPZraFpw==
-----END CERTIFICATE-----
",
    b"
-----BEGIN CERTIFICATE-----
MIIBZTCCAQugAwIBAgIIXTgB/bkN/aUwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJ
bG9jYWxob3N0MB4XDTI0MTAwNjIyMTIwM1oXDTI1MDEwNTIyMTIwM1owFDESMBAG
A1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyzSofZIX
XgLUKGumrN3SEXOMOAKXcl1VshTBzvyVwxxnD01WVLgS80/TELEltT8SMj1Cgu7I
tkDx3EVPjq4pOKNHMEUwFAYDVR0RBA0wC4IJbG9jYWxob3N0MA4GA1UdDwEB/wQE
AwICpDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwCgYIKoZIzj0EAwID
SAAwRQIhAN93g0zfB/4VyhNOaY1uCb4af4qMxcz1wp0yZ7HKAyWqAiBVPgv4X7aR
JMepVZwIWJrVhnxdcmzOuONoeLZPZraFpw==
-----END CERTIFICATE-----
",
];

static TEST_CERTS_DER: Lazy<[CertificateDer; 6]> = Lazy::new(|| {
    TEST_CERTS.map(|mut pem| rustls_pemfile::certs(&mut pem).flatten().next().unwrap())
});

const TEST_KEYS: [&[u8]; 6] = [
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
    b"\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWlbBJGC40HwzwMsd
3a6o6x75HZgRnktVwBoi6/84nPmhRANCAAQIp0lQeaYyaq2+G7g+lbDBme74sWNo
Txj2C4M0hc3472S6UWXWEtUzHpYumhJystiW8etC9yr8FMbbgQ4oB5pG
-----END PRIVATE KEY-----
",
    b"\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgi9TsF4lX49P+GIER
DjyUhMiyRZ52EsD00dGPRA4XJbahRANCAATLNKh9khdeAtQoa6as3dIRc4w4Apdy
XVWyFMHO/JXDHGcPTVZUuBLzT9MQsSW1PxIyPUKC7si2QPHcRU+Orik4
-----END PRIVATE KEY-----
",
    b"\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgs8cH8I4hrdrqDN/d
p1HENqJEFXMwcERH5JFyW/B6D/ChRANCAAT+nXv66H0vd2omUjYwWDYbGkIiGc6S
jzcyiSIULkaelVYvnEQBYefjGLQwvwbifmMrQ+hfQUT9FNbGRQ788pK9
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

#[cfg(all(test, unit_test))]
mod tests {
    use super::{get_test_certificate_and_key, TestConfigBuilder};
    use crate::{
        helpers::HelperIdentity,
        net::test::{Ports, TEST_CERTS, TEST_KEYS},
        sharding::{ShardIndex, ShardedHelperIdentity},
    };

    /// This simple test makes sure that testing networks are created properly.
    /// The network itself won't be excersized as that's tested elsewhere.
    #[test]
    fn create_4_shard_http_network() {
        let ports: Vec<Ports> = vec![
            Ports {
                ring: [10000, 10001, 10002],
                shards: [10005, 10006, 10007],
            },
            Ports {
                ring: [10010, 10011, 10012],
                shards: [10015, 10016, 10017],
            },
            Ports {
                ring: [10020, 10021, 10022],
                shards: [10025, 10026, 10027],
            },
            Ports {
                ring: [10030, 10031, 10032],
                shards: [10035, 10036, 10037],
            },
        ];
        // Providing ports and no https certs to keep this test fast
        let conf = TestConfigBuilder::default()
            .with_disable_https_option(true)
            .with_ports_by_ring(ports)
            .build();

        assert!(conf.disable_https);
        assert_eq!(conf.rings.len(), 4);
        assert_eq!(conf.shards.len(), 3);
        let shards_2 = conf.get_shards_for_helper(HelperIdentity::TWO);
        assert_eq!(shards_2.get_first_shard().config.port, Some(10006));
        let second_helper_third_shard_configs = &shards_2.servers[2];
        assert_eq!(second_helper_third_shard_configs.config.port, Some(10026));
        let leader_ring_configs = &conf.leaders_ring().servers;
        assert_eq!(leader_ring_configs[2].config.port, Some(10002));
    }

    #[test]
    #[should_panic(expected = "Found duplicate port 10001")]
    fn overlapping_ports() {
        let ports: Vec<Ports> = vec![Ports {
            ring: [10000, 10001, 10002],
            shards: [10001, 10006, 10007],
        }];
        let _ = TestConfigBuilder::default()
            .with_disable_https_option(true)
            .with_ports_by_ring(ports)
            .build();
    }

    #[test]
    fn get_assets_by_index() {
        let (c, k) = get_test_certificate_and_key(ShardedHelperIdentity::ONE_FIRST);
        assert_eq!(TEST_KEYS[0], k);
        assert_eq!(TEST_CERTS[0], c);
    }

    #[test]
    fn get_default_ports() {
        let builder = TestConfigBuilder::with_http_and_default_test_ports();
        assert_eq!(
            vec![Some(3000), Some(3001), Some(3002)],
            builder.get_ports_for_shard_index(ShardIndex(0))
        );
        assert_eq!(
            vec![Some(6001)],
            builder.get_ports_for_helper_identity(HelperIdentity::TWO)
        );
    }

    #[test]
    fn get_os_ports() {
        let builder = TestConfigBuilder::default();
        assert_eq!(3, builder.get_ports_for_shard_index(ShardIndex(0)).len());
    }
}
