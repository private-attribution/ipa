use clap::Parser;
use hyper::http::uri::Scheme;
use ipa::cli::Verbosity;

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

fn main() {
    unimplemented!();
}

#[tokio::main]
#[cfg(never)]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let _handle = args.logging.setup_logging();
    // TODO: the config should be loaded from a file, possibly with some values merged from the
    // command line arguments.
    let config = TestConfigBuilder::with_default_test_ports().build();

    let my_identity = HelperIdentity::try_from(args.identity).unwrap();
    let transport = HttpTransport::new(
        my_identity,
        config.servers[my_identity].clone(),
        Arc::new(config.network),
    );

    let query_handle = tokio::spawn({
        let transport = transport.clone();
        async move {
            let my_identity = transport.identity();
            let mut query_processor = Processor::new(transport).await;
            loop {
                tracing::debug!(
                    "Query processor is active and listening as {:?}",
                    my_identity
                );
                query_processor.handle_next().await;
            }
        }
    });
    let (addr, server_handle) = transport.bind().await;

    info!(
        "listening to {}://{}, press Enter to quit",
        args.scheme, addr
    );
    let _ = std::io::stdin().read_line(&mut String::new())?;
    server_handle.abort();
    query_handle.abort();

    Ok(())
}
