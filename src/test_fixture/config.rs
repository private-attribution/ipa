#![cfg(feature = "web-app")]

use crate::config::{NetworkConfig, ServerConfig};
use std::{fmt::Debug, net::TcpListener};

pub const DEFAULT_TEST_PORTS: [u16; 3] = [3000, 3001, 3002];

pub struct TestConfigBuilder {
    ports: Option<[u16; 3]>,
}

impl TestConfigBuilder {
    #[must_use]
    pub fn with_default_test_ports() -> Self {
        Self {
            ports: Some(DEFAULT_TEST_PORTS),
        }
    }

    #[must_use]
    pub fn with_open_ports() -> Self {
        Self { ports: None }
    }

    #[must_use]
    pub fn with_specified_ports(ports: [u16; 3]) -> Self {
        Self { ports: Some(ports) }
    }

    /// # Panics
    /// If the configuration calls for automatic port assignment and binding sockets fails.
    #[must_use]
    pub fn build(self) -> Config {
        let mut sockets = None;
        let ports = self.ports.unwrap_or_else(|| {
            let socks = [(); 3].map(|_| TcpListener::bind("127.0.0.1:0").unwrap());
            let ports = socks
                .iter()
                .map(|sock| sock.local_addr().unwrap().port())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            sockets = Some(socks);
            ports
        });
        let (network, servers) = localhost_config(ports);
        Config {
            network,
            servers,
            sockets,
        }
    }
}

pub struct Config {
    pub network: NetworkConfig,
    pub servers: [ServerConfig; 3],
    pub sockets: Option<[TcpListener; 3]>,
}

/// Creates a new config for helpers configured to run on local machine using unique port.
#[allow(clippy::missing_panics_doc)]
pub fn localhost_config<P: TryInto<u16>>(ports: [P; 3]) -> (NetworkConfig, [ServerConfig; 3])
where
    P::Error: Debug,
{
    let ports = ports.map(|v| v.try_into().expect("Failed to parse the value into u16"));
    let config_str = format!(
        r#"
# H1
[[peers]]
origin = "http://localhost:{}"

[peers.tls]
public_key = "13ccf4263cecbc30f50e6a8b9c8743943ddde62079580bc0b9019b05ba8fe924"

# H2
[[peers]]
origin = "http://localhost:{}"

[peers.tls]
public_key = "925bf98243cf70b729de1d75bf4fe6be98a986608331db63902b82a1691dc13b"

# H3
[[peers]]
origin = "http://localhost:{}"

[peers.tls]
public_key = "12c09881a1c7a92d1c70d9ea619d7ae0684b9cb45ecc207b98ef30ec2160a074"
"#,
        ports[0], ports[1], ports[2]
    );

    let network = NetworkConfig::from_toml_str(&config_str).unwrap();
    let servers = ports.map(ServerConfig::with_http_and_port);

    (network, servers)
}
