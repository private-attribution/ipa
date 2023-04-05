use clap::Parser;
use hyper::http::uri::Scheme;
use ipa::{
    cli::Verbosity,
    config::{NetworkConfig, ServerConfig},
    helpers::HelperIdentity,
    net::HttpTransport,
    AppSetup,
};
use std::{error::Error, sync::Arc};

use tracing::info;

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

fn config() -> (NetworkConfig, ServerConfig) {
    let config_str = r#"
# H1
[[peers]]
origin = "http://localhost:3000

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
    let server = ServerConfig::with_http_and_port(3000);

    (network, server)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let _handle = args.logging.setup_logging();
    // TODO: the config should be loaded from a file, possibly with some values merged from the
    // command line arguments.
    let (network_config, server_config) = config();

    let my_identity = HelperIdentity::try_from(args.identity).unwrap();
    info!("configured with identity {:?}", my_identity);

    let (setup, callbacks) = AppSetup::new();

    let transport = HttpTransport::new(
        my_identity,
        server_config,
        Arc::new(network_config),
        callbacks,
    );

    let _app = setup.connect(transport.clone());

    let (addr, server_handle) = transport.bind().await;

    info!(
        "listening to {}://{}, press Enter to quit",
        args.scheme, addr
    );
    let _ = std::io::stdin().read_line(&mut String::new())?;
    server_handle.abort();

    Ok(())
}
