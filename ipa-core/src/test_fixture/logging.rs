use std::{str::FromStr, sync::Once};

use metrics_tracing_context::MetricsLayer;
use tracing::Level;
use tracing_subscriber::{
    filter::Directive, fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
};

/// Set up logging for IPA
///
/// ## Panics
/// Does not, but compiler cannot be convinced otherwise
pub fn setup() {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
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
            .with(fmt::layer())
            .with(MetricsLayer::new())
            .init();
    });
}
