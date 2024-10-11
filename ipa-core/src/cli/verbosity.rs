use std::io::{stderr, IsTerminal};

use clap::Parser;
use tracing::{info, metadata::LevelFilter, Level};
use tracing_subscriber::{
    fmt, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
};
use ipa_metrics::{metric_name, MetricsCollector, MetricsCollectorController, MetricsProducer};
use crate::{
    error::set_global_panic_hook,
};
use crate::telemetry::metrics::BYTES_SENT;

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
    pub producer: MetricsProducer,
    pub controller: MetricsCollectorController,
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
            registry.init();
        }

        set_global_panic_hook();
        let (collector, producer, controller) = ipa_metrics::installer();

        std::thread::spawn(|| {
            collector.install();
            loop {
                MetricsCollector::with_current_mut(|store| {
                    let store = store.recv_one();
                    if !store.is_empty() {
                        tracing::info!("total bytes sent, so far: {}", store.counter_value(&metric_name!(BYTES_SENT)));
                    }
                });
            }
        });

        LoggingHandle {
            producer,
            controller
        }
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
