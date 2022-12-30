use clap::{Parser, Subcommand, ValueEnum};
use comfy_table::Table;
use raw_ipa::cli::playbook::{secure_mul, InputSource};
use raw_ipa::cli::Verbosity;
use raw_ipa::ff::{FieldType, Fp31};
use std::error::Error;
use std::fmt::Debug;
use std::path::PathBuf;

use raw_ipa::helpers::query::{QueryConfig, QueryType};
use raw_ipa::helpers::transport::http;

#[derive(Debug, Parser)]
#[clap(
    name = "mpc-client",
    about = "CLI to execute test scenarios on IPA MPC helpers"
)]
#[command(about)]
struct Args {
    #[clap(flatten)]
    logging: Verbosity,

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

    #[arg(value_enum, long, default_value_t = InputType::Fp32BitPrime, help = "Convert the input into the given field before sending to helpers")]
    input_type: InputType,

    #[arg(long, help = "helper endpoint to talk to")]
    endpoint: String,
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum InputType {
    Fp31,
    Fp32BitPrime,
    Int64,
}

#[derive(Debug, Subcommand)]
enum TestAction {
    /// Execute end-to-end multiplication.
    Multiply,
    SemiHonestIPA,
}

fn print_output<O: Debug>(values: &[Vec<O>; 3]) {
    let mut shares_table = Table::new();
    shares_table.set_header(vec!["Row", "H1", "H2", "H3"]);
    for i in 0..values[0].len() {
        shares_table.add_row(vec![
            i.to_string(),
            format!("{:?}", values[0][i]),
            format!("{:?}", values[1][i]),
            format!("{:?}", values[2][i]),
        ]);
    }

    println!("{shares_table}");
}

fn make_clients() -> [http::MpcHelperClient; 3] {
    todo!()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let _handle = args.logging.setup_logging();

    let input = InputSource::from(&args.input);
    let clients = make_clients();
    match args.action {
        TestAction::Multiply => match args.input.input_type {
            InputType::Fp31 => {
                let query_config = QueryConfig {
                    field_type: FieldType::Fp31,
                    query_type: QueryType::TestMultiply,
                };
                let query_id = clients[0].create_query(query_config).await.unwrap();
                let output =
                    secure_mul::<Fp31>(input, &clients, query_id, query_config.field_type).await;
                print_output(&output);
            }
            InputType::Fp32BitPrime => {
                // let output = secure_mul::<Fp32BitPrime>(input).await;
                // print_output(&output);
            }
            InputType::Int64 => panic!("Only field values are supported"),
        },
        TestAction::SemiHonestIPA => {}
    };

    Ok(())
}
