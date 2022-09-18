use raw_ipa::cli::Verbosity;
use raw_ipa::net::{Client, Command, MpcHandle};
use std::error::Error;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "mpc-client",
    about = "CLI to execute test scenarios on IPA MPC helpers"
)]
struct Args {
    #[structopt(flatten)]
    logging: Verbosity,

    #[structopt(short, long)]
    uri: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::from_args();
    let _handle = args.logging.setup_logging();

    // TODO: Start MPC helpers and discover
    let client = Client::new(args.uri.as_str());

    let response = client.execute(Command::Echo("hello".into())).await?;

    println!(
        "Response: {:?}",
        String::from_utf8_lossy(response.as_slice())
    );

    Ok(())
}
