use clap::Parser;
use hyper::http::uri::Scheme;
use raw_ipa::{
    cli::{helpers_config, Verbosity},
    helpers::{HelperIdentity, Transport},
    net::{discovery::PeerDiscovery, HttpTransport},
    query::Processor,
};
use std::error::Error;
use std::sync::Arc;

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

    let my_identity = HelperIdentity::try_from(args.identity).unwrap();
    let helper = HttpTransport::new(my_identity, Arc::new(config.peers().clone()));
    // TODO: helper identities construction needs to be made more ergonomic
    let mut all_identities = HelperIdentity::make_three()
        .into_iter()
        .filter(|id| id != &my_identity);

    let processor_identities = [
        my_identity,
        all_identities.next().unwrap(),
        all_identities.next().unwrap(),
    ];

    let query_handle = tokio::spawn({
        let helper = helper.clone();
        async move {
            let my_identity = helper.identity();
            let mut query_processor = Processor::new(helper, processor_identities).await;
            loop {
                tracing::debug!(
                    "Query processor is active and listening as {:?}",
                    my_identity
                );
                query_processor.handle_next().await;
            }
        }
    });
    let (addr, server_handle) = helper.bind().await;

    info!(
        "listening to {}://{}, press Enter to quit",
        args.scheme, addr
    );
    let _ = std::io::stdin().read_line(&mut String::new())?;
    server_handle.abort();
    query_handle.abort();

    Ok(())
}
