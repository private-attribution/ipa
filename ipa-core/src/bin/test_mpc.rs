use std::{error::Error, fmt::Debug, ops::Add, path::PathBuf};

use clap::{Parser, Subcommand};
use generic_array::ArrayLength;
use hyper::http::uri::Scheme;
use ipa_core::{
    cli::{
        playbook::{make_clients, secure_add, secure_mul, validate, InputSource},
        Verbosity,
    },
    ff::{Field, FieldType, Fp31, Fp32BitPrime, Serializable, U128Conversions},
    helpers::query::{
        QueryConfig,
        QueryType::{TestAddInPrimeField, TestMultiply},
    },
    net::{Helper, IpaHttpClient},
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

    #[arg(
        long,
        conflicts_with = "input_file",
        help = "Instead of taking input from a file, generate the given number of field values for input"
    )]
    generate: Option<u64>,
}

impl From<&CommandInput> for InputSource {
    fn from(source: &CommandInput) -> Self {
        if let Some(ref file_name) = source.input_file {
            InputSource::from_file(file_name)
        } else if let Some(count) = source.generate {
            InputSource::from_generator(count)
        } else {
            InputSource::from_stdin()
        }
    }
}

#[derive(Debug, Subcommand)]
enum TestAction {
    /// Execute end-to-end multiplication.
    Multiply,
    /// Execute end-to-end simple addition circuit that uses prime fields.
    /// All helpers add their shares locally and set the resulting share to be the
    /// sum. No communication is required to run the circuit.
    AddInPrimeField,
    /// A test protocol for sharded MPCs. The goal here is to use
    /// both shard-to-shard and helper-to-helper communication channels.
    /// This is exactly what shuffle does and that's why it is picked
    /// for this purpose.
    ShardedShuffle,
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
        TestAction::AddInPrimeField => add(&args, &clients).await,
        TestAction::ShardedShuffle => sharded_shuffle(&args, &clients).await,
    };

    Ok(())
}

async fn multiply_in_field<F>(args: &Args, helper_clients: &[IpaHttpClient<Helper>; 3])
where
    F: Field + U128Conversions + IntoShares<AdditiveShare<F>>,
    <F as Serializable>::Size: Add<<F as Serializable>::Size>,
    <<F as Serializable>::Size as Add<<F as Serializable>::Size>>::Output: ArrayLength,
{
    let input = InputSource::from(&args.input);
    let input_rows = input.iter::<(F, F)>().collect::<Vec<_>>();
    let query_config = QueryConfig::new(TestMultiply, args.input.field, input_rows.len()).unwrap();

    let query_id = helper_clients[0].create_query(query_config).await.unwrap();
    let expected = input_rows.iter().map(|(a, b)| *a * *b).collect::<Vec<_>>();
    let actual = secure_mul(input_rows, helper_clients, query_id).await;

    validate(&expected, &actual);
}

async fn multiply(args: &Args, helper_clients: &[IpaHttpClient<Helper>; 3]) {
    match args.input.field {
        FieldType::Fp31 => multiply_in_field::<Fp31>(args, helper_clients).await,
        FieldType::Fp32BitPrime => multiply_in_field::<Fp32BitPrime>(args, helper_clients).await,
    };
}

async fn add_in_field<F>(args: &Args, helper_clients: &[IpaHttpClient<Helper>; 3])
where
    F: Field + U128Conversions + IntoShares<AdditiveShare<F>>,
    <F as Serializable>::Size: Add<<F as Serializable>::Size>,
    <<F as Serializable>::Size as Add<<F as Serializable>::Size>>::Output: ArrayLength,
{
    let input = InputSource::from(&args.input);
    // compute the sum as we are iterating through the input. That avoid cloning the iterator
    let mut expected = F::ZERO;
    let input_rows = input.known_size_iter().map(F::truncate_from).map(|v| {
        expected += v;
        v
    });
    let query_config =
        QueryConfig::new(TestAddInPrimeField, args.input.field, input_rows.len()).unwrap();

    let query_id = helper_clients[0].create_query(query_config).await.unwrap();
    let actual = secure_add(input_rows, helper_clients, query_id).await;

    validate(&vec![expected], &vec![actual]);
}

async fn add(args: &Args, helper_clients: &[IpaHttpClient<Helper>; 3]) {
    match args.input.field {
        FieldType::Fp31 => add_in_field::<Fp31>(args, helper_clients).await,
        FieldType::Fp32BitPrime => add_in_field::<Fp32BitPrime>(args, helper_clients).await,
    };
}

async fn sharded_shuffle(_args: &Args, _helper_clients: &[IpaHttpClient<Helper>; 3]) {
    unimplemented!()
}
