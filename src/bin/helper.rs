use clap::Parser;
use hyper::http::uri::Scheme;

use raw_ipa::cli::Verbosity;
use std::error::Error;
use std::sync::Arc;

use raw_ipa::cli::helpers_config;
use raw_ipa::helpers::transport::http::discovery::PeerDiscovery;
use raw_ipa::helpers::transport::http::HttpTransport;
use raw_ipa::helpers::HelperIdentity;
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let _handle = args.logging.setup_logging();
    let config = helpers_config();

    let helper = HttpTransport::new(
        HelperIdentity::try_from(args.identity).unwrap(),
        Arc::new(config.peers_map().clone()),
    );
    let (addr, server_handle) = helper.bind().await;

    info!(
        "listening to {}://{}, press Enter to quit",
        args.scheme, addr
    );
    let _ = std::io::stdin().read_line(&mut String::new())?;
    server_handle.abort();

    Ok(())
}
