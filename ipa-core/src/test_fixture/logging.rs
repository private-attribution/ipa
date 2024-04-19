use std::sync::Once;

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

            use metrics_tracing_context::MetricsLayer;
            use tracing::Level;
            use tracing_subscriber::{
                filter::Directive, fmt, fmt::format::FmtSpan, layer::SubscriberExt,
                util::SubscriberInitExt, EnvFilter,
            };

            let default_directive = if let Some(crate_name) = option_env!("CARGO_CRATE_NAME") {
                // only print IPA crate logging by default
                Directive::from_str(&format!("{crate_name}=INFO")).unwrap()
            } else {
                Level::INFO.into()
            };

            tracing_subscriber::registry()
                .with(
                    EnvFilter::builder()
                        .with_default_directive(default_directive)
                        .from_env_lossy(),
                )
                .with(
                    fmt::layer()
                        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
                        .with_test_writer(),
                )
                .with(MetricsLayer::new())
                .init();
        }
    });
}
