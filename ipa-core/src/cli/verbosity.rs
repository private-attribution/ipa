use std::{
    fs::OpenOptions,
    io::{stderr, IsTerminal},
    path::PathBuf,
};

use clap::Parser;
use tracing::{info, metadata::LevelFilter, Level};
use tracing_subscriber::{
    fmt, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
};

use crate::{
    cli::{install_collector, metric_collector::CollectorHandle},
    error::set_global_panic_hook,
};

#[derive(Debug, Parser)]
pub struct Verbosity {
    /// Silence all output
    #[clap(short, long, global = true)]
    quiet: bool,

    /// Verbose mode (-v, or -vv for even more verbose)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[arg(long, help = "Specify the output file for logs")]
    log_file: Option<PathBuf>,
}

pub struct LoggingHandle {
    pub metrics_handle: CollectorHandle,
}

impl Verbosity {
    /// Sets up logging and metrics infrastructure
    ///
    /// ## Panics
    /// If metrics failed to setup
    #[must_use]
    pub fn setup_logging(&self) -> LoggingHandle {
        let filter_layer = self.log_filter();
        info!("Logging setup at level {}", filter_layer);

        let stderr_writer = fmt::layer()
            .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
            .with_ansi(std::io::stderr().is_terminal())
            .with_writer(stderr);

        let registry = tracing_subscriber::registry()
            .with(filter_layer)
            .with(stderr_writer);

        if let Some(path) = &self.log_file {
            let log_file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
                .unwrap_or_else(|e| panic!("failed to open log file {path:?}: {e}"));
            let file_writer = fmt::layer()
                .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
                .with_ansi(false)
                .with_writer(log_file);

            // that's the only stderr message that should appear to give a hint where
            // the logs are written to
            tracing::info!("Logs will be written to {path:?}");
            registry.with(file_writer).init();
        } else {
            registry.init();
        }

        let metrics_handle = install_collector().expect("Can install metrics");

        let handle = LoggingHandle { metrics_handle };
        set_global_panic_hook();

        handle
    }

    fn log_filter(&self) -> EnvFilter {
        EnvFilter::builder()
            .with_default_directive(
                if self.quiet {
                    LevelFilter::OFF
                } else {
                    LevelFilter::from_level(match self.verbose {
                        0 => Level::INFO,
                        1 => Level::DEBUG,
                        _ => Level::TRACE,
                    })
                }
                .into(),
            )
            .from_env_lossy()
    }
}
