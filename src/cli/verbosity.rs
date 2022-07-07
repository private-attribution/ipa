use std::io;
use structopt::StructOpt;
use tracing::metadata::LevelFilter;
use tracing::{info, Level};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, StructOpt)]
pub struct Verbosity {
    /// Silence all output
    #[structopt(short = "q", long = "quiet", global = true)]
    quiet: bool,

    /// Verbose mode (-v, -vv, -vvv, etc)
    #[structopt(short = "v", long = "verbose", global = true, parse(from_occurrences))]
    verbose: usize,
}

fn from_verbosity(quiet: bool, verbose: usize) -> LevelFilter {
    if quiet {
        LevelFilter::OFF
    } else {
        LevelFilter::from_level(match verbose {
            0 => Level::ERROR,
            1 => Level::WARN,
            2 => Level::INFO,
            3 => Level::DEBUG,
            _ => Level::TRACE,
        })
    }
}

impl Verbosity {
    pub fn setup_logging(&self) {
        let filter_layer = from_verbosity(self.quiet, self.verbose);
        let fmt_layer = fmt::layer().without_time().with_writer(io::stderr);

        tracing_subscriber::registry()
            .with(filter_layer)
            .with(fmt_layer)
            .init();
        info!("Logging setup at level {}", filter_layer);
    }
}
