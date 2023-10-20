use std::{error::Error, fmt::Debug, ops::Add, path::PathBuf};

use clap::{Parser, Subcommand};
use generic_array::ArrayLength;
use hyper::http::uri::Scheme;
use ipa::{
    cli::{
        playbook::{make_clients, secure_mul, validate, InputSource},
        Verbosity,
    },
    ff::{Field, FieldType, Fp31, Fp32BitPrime, Serializable},
    helpers::query::{QueryConfig, QueryType::TestMultiply},
    net::MpcHelperClient,
    secret_sharing::{replicated::semi_honest::AdditiveShare, IntoShares},
};

#[derive(Debug, Parser)]
#[clap(
    name = "mpc-client",
    about = "CLI to execute test scenarios on IPA MPC helpers"
)]
#[command(about)]
struct Args {
    #[clap(flatten)]
    logging: Verbosity,

    /// Path to helper network configuration file
    #[arg(long)]
    network: Option<PathBuf>,

    /// Use insecure HTTP
    #[arg(short = 'k', long)]
    disable_https: bool,

    /// Seconds to wait for server to be running
    #[arg(short, long, default_value_t = 0)]
    wait: usize,

    #[clap(flatten)]
    input: CommandInput,

    #[command(subcommand)]
    action: TestAction,
}

#[derive(Debug, Parser)]
pub struct CommandInput {
    #[arg(
        long,
        help = "Read the input from the provided file, instead of standard input"
    )]
    input_file: Option<PathBuf>,

    #[arg(value_enum, long, default_value_t = FieldType::Fp32BitPrime, help = "Convert the input into the given field before sending to helpers")]
    field: FieldType,
}

impl From<&CommandInput> for InputSource {
    fn from(source: &CommandInput) -> Self {
        if let Some(ref file_name) = source.input_file {
            InputSource::from_file(file_name)
        } else {
            InputSource::from_stdin()
        }
    }
}

#[derive(Debug, Subcommand)]
enum TestAction {
    /// Execute end-to-end multiplication.
    Multiply,
}

#[derive(Debug, clap::Args)]
struct GenInputArgs {
    /// Maximum records per user
    #[clap(long)]
    max_per_user: u32,
    /// number of breakdowns
    breakdowns: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let _handle = args.logging.setup_logging();

    let scheme = if args.disable_https {
        Scheme::HTTP
    } else {
        Scheme::HTTPS
    };

    let (clients, _) = make_clients(args.network.as_deref(), scheme, args.wait).await;
    match args.action {
        TestAction::Multiply => multiply(&args, &clients).await,
    };

    Ok(())
}

async fn multiply_in_field<F: Field>(args: &Args, helper_clients: &[MpcHelperClient; 3])
where
    F: Field + IntoShares<AdditiveShare<F>>,
    <F as Serializable>::Size: Add<<F as Serializable>::Size>,
    <<F as Serializable>::Size as Add<<F as Serializable>::Size>>::Output: ArrayLength,
{
    let input = InputSource::from(&args.input);
    let input_rows = input.iter::<(F, F)>().collect::<Vec<_>>();
    let query_config = QueryConfig::new(TestMultiply, args.input.field, input_rows.len()).unwrap();

    let query_id = helper_clients[0].create_query(query_config).await.unwrap();
    let expected = input_rows.iter().map(|(a, b)| *a * *b).collect::<Vec<_>>();
    let actual = secure_mul(input_rows, &helper_clients, query_id).await;

    validate(&expected, &actual);
}

async fn multiply(args: &Args, helper_clients: &[MpcHelperClient; 3]) {
    match args.input.field {
        FieldType::Fp31 => multiply_in_field::<Fp31>(&args, helper_clients).await,
        FieldType::Fp32BitPrime => multiply_in_field::<Fp32BitPrime>(&args, helper_clients).await,
    };
}
