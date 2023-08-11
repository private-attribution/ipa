use std::io::stderr;

use clap::Parser;
use metrics_tracing_context::MetricsLayer;
use tracing::{info, metadata::LevelFilter, Level};
use tracing_subscriber::{
    fmt, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
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
        let filter_layer = self.level_filter();
        let fmt_layer = fmt::layer()
            .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
            .with_writer(stderr);

        tracing_subscriber::registry()
            .with(self.level_filter())
            .with(fmt_layer)
            .with(MetricsLayer::new())
            .init();

        let handle = LoggingHandle {
            metrics_handle: (!self.quiet).then(install_collector),
        };
        set_global_panic_hook();

        info!("Logging setup at level {}", filter_layer);

        handle
    }

    fn level_filter(&self) -> LevelFilter {
        if self.quiet {
            LevelFilter::OFF
        } else {
            LevelFilter::from_level(match self.verbose {
                0 => Level::INFO,
                1 => Level::DEBUG,
                _ => Level::TRACE,
            })
        }
    }
}
