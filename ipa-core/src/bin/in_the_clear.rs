use std::{error::Error, fs::File, io::Write, num::NonZeroU32, path::PathBuf};

use clap::Parser;
use ipa_core::{
    cli::{playbook::InputSource, Verbosity},
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
#[clap(name = "in_the_clear", about = "In the Clear CLI")]
#[command(about)]
struct Args {
    #[clap(flatten)]
    logging: Verbosity,

    #[clap(flatten)]
    input: CommandInput,

    /// The destination file for output.
    #[arg(long, value_name = "OUTPUT_FILE")]
    output_file: PathBuf,

    #[arg(long, default_value = "20")]
    max_breakdown_key: NonZeroU32,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let _handle = args.logging.setup_logging();

    let input = InputSource::from(&args.input);

    let input_rows = input.iter::<TestHybridRecord>();
    let expected = hybrid_in_the_clear(
        input_rows,
        usize::try_from(args.max_breakdown_key.get()).unwrap(),
    );

    let mut file = File::options()
        .write(true)
        .create_new(true)
        .open(&args.output_file)
        .map_err(|e| {
            format!(
                "Failed to create output file {}: {e}",
                &args.output_file.display()
            )
        })?;

    write!(file, "{}", serde_json::to_string_pretty(&expected)?)?;

    Ok(())
}
