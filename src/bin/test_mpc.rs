use clap::{Parser, Subcommand, ValueEnum};
use raw_ipa::{cli::Verbosity, helpers::Role, net::MpcHelperClient};
use std::error::Error;
use std::fmt::Debug;
use std::future::Future;
use std::path::PathBuf;
use comfy_table::Table;
use raw_ipa::cli::playbook;
use raw_ipa::cli::playbook::{InputSource, Scenario, secure_mul};

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
    #[arg(long, help = "Read the input from the provided file, instead of standard input")]
    input_file: Option<PathBuf>,
    #[arg(value_enum, long, default_value_t = InputType::Fp32BitPrime, help = "Convert the input into the given field before sending to helpers")]
    input_type: InputType,
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
}

fn print_output<O: Debug>(input: &[Vec<O>; 3]) {
    let mut shares_table = Table::new();
    shares_table.set_header(vec!["Row", "H1", "H2", "H3"]);
    for i in 0..input[0].len() {
        shares_table.add_row(vec![
            i.to_string(),
            format!("{:?}", input[0][i]),
            format!("{:?}", input[1][i]),
            format!("{:?}", input[2][i]),
        ]);
    }

    println!("{}", shares_table);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = Args::parse();
    let _handle = args.logging.setup_logging();

    // let mut input = InputSource::from(&args.input);
    match args.action {
        TestAction::Multiply => {
            // let output = execute(&mut args.input, |source| async {
            //     secure_mul(source).await
            // });
            // print_output(&output);
        }
    }

    Ok(())
}