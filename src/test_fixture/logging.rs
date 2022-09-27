use std::sync::Once;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub fn setup() {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        tracing_subscriber::registry()
            .with(EnvFilter::from_default_env())
            .with(fmt::layer())
            .init();
    });
}
