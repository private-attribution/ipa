use std::{
    error::Error,
    path::{Path, PathBuf},
};

use clap::Parser;
use ipa_core::{
    cli::playbook::InputSource,
    test_fixture::hybrid::{hybrid_in_the_clear, TestHybridRecord},
};

#[derive(Debug, Parser)]
pub struct CommandInput {
    #[arg(
        long,
        help = "Read the input from the provided file, instead of standard input"
    )]
    input_file: Option<PathBuf>,
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

#[derive(Debug, Parser)]
#[clap(name = "rc", about = "Report Collector CLI")]
#[command(about)]
struct Args {
    #[clap(flatten)]
    input: CommandInput,

    /// The destination file for output.
    #[arg(long, value_name = "OUTPUT_FILE")]
    output_file: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let input = InputSource::from(&args.input);

    let input_rows = input.iter::<TestHybridRecord>().collect::<Vec<_>>();
    let expected = hybrid_in_the_clear(&input_rows, 10);

    let mut file = File::options()
        .write(true)
        .create_new(true)
        .open(args.output_file)
        .map_err(|e| {
            format!(
                "Failed to create output file {}: {e}",
                args.output_file.display()
            )
        })?;

    write!(file, "{}", serde_json::to_string_pretty(&expected)?)?;

    Ok(())
}
