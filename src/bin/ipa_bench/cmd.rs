use crate::sample::Sample;

use super::attribute::generate_report;
use super::gen_events::generate_events;

use log::{debug, error, info};
use rand::rngs::StdRng;
use rand::SeedableRng;
use raw_ipa::cli::Verbosity;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::{io, process};
use structopt::StructOpt;

const DEFAULT_EVENT_GEN_COUNT: u32 = 100_000;

#[derive(Debug, StructOpt)]
pub struct CommonArgs {
    #[structopt(flatten)]
    pub logging: Verbosity,

    #[structopt(
        short,
        long,
        global = true,
        help = "Write the result to the file.",
        parse(from_os_str)
    )]
    output_file: Option<PathBuf>,

    #[structopt(long, global = true, help = "Overwrite the specified output file.")]
    overwrite: bool,
}

impl CommonArgs {
    fn get_output(&self) -> Result<Box<dyn io::Write>, io::Error> {
        match self.output_file {
            Some(ref path) => {
                let mut file = File::options();

                if self.overwrite {
                    file.truncate(true).create(true);
                } else {
                    file.create_new(true);
                }

                file.write(true)
                    .open(path)
                    .map(|f| Box::new(f) as Box<dyn io::Write>)
            }
            None => Ok(Box::new(io::stdout())),
        }
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "ipa_bench", about = "Synthetic data test harness for IPA")]
pub struct Args {
    #[structopt(flatten)]
    pub common: CommonArgs,

    #[structopt(subcommand)]
    pub cmd: Command,
}

#[derive(Debug, StructOpt)]
#[structopt(name = "command")]
pub enum Command {
    #[structopt(about = "Generate synthetic events.")]
    GenEvents {
        #[structopt(
            short,
            long,
            default_value = "1",
            help = "Multiply the number of events generated by the scale factor. For example, --scale-factor=100 generates 10,000,000 synthetic events."
        )]
        scale_factor: u32,

        #[structopt(
            short,
            long,
            help = "Random generator seed. Setting the seed allows reproduction of the synthetic data exactly."
        )]
        random_seed: Option<u64>,

        #[structopt(
            short,
            long,
            default_value = "0",
            help = "Simulate ads created in this epoch. Impressions and conversions for a given ad may happen in the next epoch."
        )]
        epoch: u8,

        #[structopt(long, help = "Output secret shared values")]
        secret_share: bool,

        #[structopt(
            short,
            long,
            help = "Configuration file containing distributions data.",
            parse(from_os_str)
        )]
        config_file: PathBuf,
    },

    #[structopt(about = "Execute a specified attribution logic.")]
    Attribute {
        #[structopt(
            short,
            long,
            help = "File containing source and trigger events. If not set, stdin will be used.",
            parse(from_os_str)
        )]
        input_file: Option<PathBuf>,

        #[structopt(
            short,
            long,
            default_value = "7",
            help = "Attribution window in days. Trigger events within the window are attributed to the preceeding source event."
        )]
        attribution_window: u32,

        #[structopt(
            short,
            long,
            possible_values = &["LastTouch"],
            default_value = "LastTouch",
        )]
        model: String,
    },
}

impl Command {
    pub fn dispatch(&self, common: &CommonArgs) {
        info!("Command {:?}", self);

        match self {
            Self::GenEvents {
                scale_factor,
                random_seed,
                epoch,
                secret_share,
                config_file,
            } => {
                Command::gen_events(
                    common,
                    *scale_factor,
                    random_seed,
                    *epoch,
                    *secret_share,
                    config_file,
                );
            }

            Self::Attribute {
                input_file,
                attribution_window,
                model,
            } => Command::attribute(common, input_file, *attribution_window, model),
        }
    }

    fn gen_events(
        common: &CommonArgs,
        scale_factor: u32,
        random_seed: &Option<u64>,
        epoch: u8,
        secret_share: bool,
        config_file: &Path,
    ) {
        let mut input = Command::get_input(&Some(config_file.to_path_buf())).unwrap_or_else(|e| {
            error!("Failed to open the input file. {}", e);
            process::exit(1);
        });

        let mut out = common.get_output().unwrap_or_else(|e| {
            error!("Failed to open the output file. {}", e);
            process::exit(1);
        });

        info!(
            "scale: {}, seed: {:?}, epoch: {}",
            scale_factor, random_seed, epoch
        );
        debug!(
            "Total number of events to generate: {}",
            DEFAULT_EVENT_GEN_COUNT * scale_factor
        );

        let config = serde_json::from_reader(&mut input).unwrap();
        let sample = Sample::new(&config);

        let mut rng = random_seed.map_or(StdRng::from_entropy(), StdRng::seed_from_u64);
        let mut ss_rng = random_seed.map_or(StdRng::from_entropy(), StdRng::seed_from_u64);

        let (s_count, t_count) = generate_events(
            &sample,
            DEFAULT_EVENT_GEN_COUNT * scale_factor,
            epoch,
            secret_share,
            &mut rng,
            &mut ss_rng,
            &mut out,
        );

        info!("{} source events generated", s_count);
        info!("{} trigger events generated", t_count);
        info!(
            "trigger/source ratio: {}",
            f64::from(t_count) / f64::from(s_count)
        );
    }

    fn attribute(
        common: &CommonArgs,
        input_file: &Option<PathBuf>,
        attribution_window: u32,
        model: &str,
    ) {
        let mut input = Command::get_input(input_file).unwrap_or_else(|e| {
            error!("Failed to open the input file. {}", e);
            process::exit(1);
        });

        let mut out = common.get_output().unwrap_or_else(|e| {
            error!("Failed to open the output file. {}", e);
            process::exit(1);
        });

        info!(
            "attribution_window: {}, model: {}",
            attribution_window, model
        );

        generate_report(&mut input, attribution_window, model, &mut out);
    }

    fn get_input(path: &Option<PathBuf>) -> Result<Box<dyn io::Read>, io::Error> {
        match path {
            Some(ref path) => File::open(path).map(|f| Box::new(f) as Box<dyn io::Read>),
            None => Ok(Box::new(io::stdin())),
        }
    }
}
