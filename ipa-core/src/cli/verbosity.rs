use std::io::{stderr, IsTerminal};

use clap::Parser;
use metrics_tracing_context::MetricsLayer;
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
}

pub struct LoggingHandle {
    #[allow(dead_code)] // we care about handle's drop semantic so it is ok to not read it
    metrics_handle: Option<CollectorHandle>,
}

impl Verbosity {
    #[must_use]
    pub fn setup_logging(&self) -> LoggingHandle {
        let filter_layer = self.log_filter();
        info!("Logging setup at level {}", filter_layer);

        let fmt_layer = fmt::layer()
            .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
            .with_ansi(std::io::stderr().is_terminal())
            .with_writer(stderr);

        let registry = tracing_subscriber::registry()
            .with(filter_layer)
            .with(fmt_layer);

        if cfg!(feature = "disable-metrics") {
            registry.init();
        } else {
            registry.with(MetricsLayer::new()).init();
        }

        let handle = LoggingHandle {
            metrics_handle: (!self.quiet && !cfg!(feature = "disable-metrics"))
                .then(install_collector),
        };
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
