use clap::Parser;
use raw_ipa::cli::Verbosity;
use raw_ipa::net::MpcHelperClient;
use std::error::Error;

#[derive(Debug, Parser)]
#[clap(
    name = "mpc-client",
    about = "CLI to execute test scenarios on IPA MPC helpers"
)]
struct Args {
    #[clap(flatten)]
    logging: Verbosity,

    #[arg(short, long)]
    uri: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let _handle = args.logging.setup_logging();

    // TODO: Start MPC helpers and discover
    let client = MpcHelperClient::with_str_addr(&args.uri)?;

    let response = client.echo("hello").await?;

    println!(
        "Response: {:?}",
        String::from_utf8_lossy(response.as_slice())
    );

    Ok(())
}
