//! Ideally, this binary would only be built when:
//!  * the `web-app` feature is active, AND
//!  * the `test-fixture` feature is not active.
//!
//! Unfortunately, that is not possible to specify in Cargo.toml, so it is (somewhat awkwardly)
//! written to build and fail at runtime when both features are active.
//!
//! See `TransportImpl` for further discussion.

use std::error::Error;

#[cfg(all(feature = "test-fixture", feature = "web-app"))]
mod stub {
    use std::error::Error;

    pub async fn main() -> Result<(), Box<dyn Error>> {
        Err(format!(
            "{} is not available when both the test-fixture and web-app features are enabled",
            env!("CARGO_BIN_NAME"),
        )
        .into())
    }
}

#[cfg(not(all(feature = "test-fixture", feature = "web-app")))]
mod real {
    use clap::Parser;
    use hyper::http::uri::Scheme;
    use ipa::{
        cli::Verbosity,
        config::{NetworkConfig, ServerConfig},
        helpers::HelperIdentity,
        net::{BindTarget, HttpTransport},
        AppSetup,
    };
    use std::{error::Error, sync::Arc};

    use tracing::info;

    #[cfg(all(target_arch = "x86_64", not(target_env = "msvc")))]
    #[global_allocator]
    static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

    #[derive(Debug, Parser)]
    #[clap(name = "mpc-helper", about = "CLI to start an MPC helper endpoint")]
    struct Args {
        /// Configure logging.
        #[clap(flatten)]
        logging: Verbosity,

        /// Indicates which identity this helper has
        #[arg(short, long)]
        identity: usize,

        /// Port to listen. If not specified, will ask Kernel to assign the port
        #[arg(short, long)]
        port: Option<u16>,

        /// Indicates whether to start HTTP or HTTPS endpoint
        #[arg(short, long, default_value = "http")]
        scheme: Scheme,
    }

    fn config(identity: HelperIdentity) -> (NetworkConfig, ServerConfig) {
        let port = match identity {
            HelperIdentity::ONE => 3000,
            HelperIdentity::TWO => 3001,
            HelperIdentity::THREE => 3002,
            _ => panic!("invalid helper identity {:?}", identity),
        };

        let config_str = r#"
# H1
[[peers]]
origin = "http://localhost:3000"

[peers.tls]
public_key = "13ccf4263cecbc30f50e6a8b9c8743943ddde62079580bc0b9019b05ba8fe924"

# H2
[[peers]]
origin = "http://localhost:3001"

[peers.tls]
public_key = "925bf98243cf70b729de1d75bf4fe6be98a986608331db63902b82a1691dc13b"

# H3
[[peers]]
origin = "http://localhost:3002"

[peers.tls]
public_key = "12c09881a1c7a92d1c70d9ea619d7ae0684b9cb45ecc207b98ef30ec2160a074"
"#;

        let network = NetworkConfig::from_toml_str(&config_str).unwrap();
        let server = ServerConfig::with_http_and_port(port);

        (network, server)
    }

    pub async fn main() -> Result<(), Box<dyn Error>> {
        let args = Args::parse();
        let _handle = args.logging.setup_logging();

        let my_identity = HelperIdentity::try_from(args.identity).unwrap();
        info!("configured with identity {:?}", my_identity);

        // TODO(596): the config should be loaded from a file, possibly with some values merged from the
        // command line arguments.
        let (network_config, server_config) = config(my_identity);

        let (setup, callbacks) = AppSetup::new();

        let (transport, server) = HttpTransport::new(
            my_identity,
            //server_config,
            Arc::new(network_config),
            callbacks,
        );

        let _app = setup.connect(transport.clone());

        // TODO(596): Bind target was moved here from `HttpTransport::bind()`. It needs to come
        // from a config file. Probably, the config should be stored in the server when
        // constructed, and the argument to server.bind() should go away.
        let (addr, server_handle) = server
            .bind(BindTarget::Http(
                format!("0.0.0.0:{}", server_config.port.unwrap())
                    .parse()
                    .unwrap(),
            ))
            .await;

        info!(
            "listening to {}://{}, press Enter to quit",
            args.scheme, addr
        );
        let _ = std::io::stdin().read_line(&mut String::new())?;
        server_handle.abort();

        Ok(())
    }
}

#[cfg(all(feature = "test-fixture", feature = "web-app"))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    stub::main().await
}

#[cfg(not(all(feature = "test-fixture", feature = "web-app")))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    real::main().await
}
