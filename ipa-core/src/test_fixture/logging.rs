use std::sync::Once;

use tracing_subscriber::fmt::format::FmtSpan;

/// Set up logging for IPA
///
/// ## Panics
/// Does not, but compiler cannot be convinced otherwise
pub fn setup() {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        #[cfg(feature = "tokio-console")]
        {
            console_subscriber::init();
        }

        #[cfg(not(feature = "tokio-console"))]
        {
            use std::str::FromStr;

            use tracing::Level;
            use tracing_subscriber::{
                filter::Directive, fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
            };

            let default_directive = if let Some(crate_name) = option_env!("CARGO_CRATE_NAME") {
                // only print IPA crate logging by default
                Directive::from_str(&format!("{crate_name}=INFO")).unwrap()
            } else {
                Level::INFO.into()
            };

            let fmt_layer = fmt::layer()
                .with_test_writer()
                .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE);

            tracing_subscriber::registry()
                .with(
                    EnvFilter::builder()
                        .with_default_directive(default_directive)
                        .from_env_lossy(),
                )
                .with(fmt_layer)
                .with(ipa_metrics_tracing::MetricsPartitioningLayer)
                .init();
        }
    });
}
