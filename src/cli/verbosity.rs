use metrics_tracing_context::MetricsLayer;

use std::io::stderr;

use crate::cli::install_collector;
use crate::cli::metric_collector::CollectorHandle;
use structopt::StructOpt;
use tracing::{info, metadata::LevelFilter, Level};
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

pub struct LoggingHandle {
    #[allow(dead_code)] // we care about handle's drop semantic so it is ok to not read it
    metrics_handle: Option<CollectorHandle>,
}

impl Verbosity {
    #[must_use]
    pub fn setup_logging(&self) -> LoggingHandle {
        let filter_layer = self.level_filter();
        let fmt_layer = fmt::layer().without_time().with_writer(stderr);

        tracing_subscriber::registry()
            .with(self.level_filter())
            .with(fmt_layer)
            .with(MetricsLayer::new())
            .init();

        let handle = LoggingHandle {
            metrics_handle: (!self.quiet).then(install_collector),
        };

        info!("Logging setup at level {}", filter_layer);

        handle
    }

    fn level_filter(&self) -> LevelFilter {
        if self.quiet {
            LevelFilter::OFF
        } else {
            LevelFilter::from_level(match self.verbose {
                0 => Level::ERROR,
                1 => Level::WARN,
                2 => Level::INFO,
                3 => Level::DEBUG,
                _ => Level::TRACE,
            })
        }
    }
}
