use std::sync::Once;
use metrics_tracing_context::MetricsLayer;
use tracing::Level;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub fn setup() {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        tracing_subscriber::registry()
            .with(EnvFilter::builder()
                      .with_default_directive(Level::INFO.into()).from_env_lossy())
            .with(fmt::layer())
            .with(MetricsLayer::new())
            .init();
    });
}
