#![cfg(feature = "web-app")]

use crate::config::{NetworkConfig, ServerConfig};
use std::{array, fmt::Debug, net::TcpListener};

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
url = "http://localhost:{}"
[[client_config]]
public_key = ""

# H2
[[peers]]
url = "http://localhost:{}"
[[client_config]]
public_key = ""

# H3
[[peers]]
url = "http://localhost:{}"
[[client_config]]
public_key = ""

"#,
        ports[0], ports[1], ports[2]
    );

    let network = NetworkConfig::from_toml_str(&config_str).unwrap();
    let servers = ports.map(|port| ServerConfig::insecure_http_port(port, false));

    (network, servers)
}
