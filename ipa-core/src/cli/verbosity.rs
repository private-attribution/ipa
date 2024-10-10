use std::io::{stderr, IsTerminal};

use clap::Parser;
use tracing::{info, metadata::LevelFilter, Level};
use tracing_subscriber::{
    fmt, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
};

use crate::{
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
}

pub struct LoggingHandle;

impl Verbosity {
    #[must_use]
    pub fn setup_logging(&self) -> LoggingHandle {
        let filter_layer = self.log_filter();
        let fmt_layer = fmt::layer()
            .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
            .with_ansi(std::io::stderr().is_terminal())
            .with_writer(stderr);

        tracing_subscriber::registry()
            .with(self.log_filter())
            .with(fmt_layer)
            .init();

        set_global_panic_hook();

        info!("Logging setup at level {}", filter_layer);

        LoggingHandle
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
