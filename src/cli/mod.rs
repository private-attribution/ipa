mod metric_collector;
#[cfg(feature = "web-app")]
pub mod playbook;
mod verbosity;

pub use metric_collector::{install_collector, CollectorHandle};
pub use verbosity::Verbosity;

#[must_use]
#[cfg(feature = "web-app")]
#[cfg(never)]
pub fn helpers_config() -> net::discovery::Conf {
    use test_fixture::net::localhost_config;
    localhost_config([3001, 3002, 3003])
}
