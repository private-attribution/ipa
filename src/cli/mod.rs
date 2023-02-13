mod metric_collector;
#[cfg(feature = "web-app")]
pub mod playbook;
mod verbosity;

#[cfg(feature = "web-app")]
use crate::{net::discovery::Conf, test_fixture::net::localhost_config};
pub use metric_collector::{install_collector, CollectorHandle};
pub use verbosity::Verbosity;

#[must_use]
#[cfg(feature = "web-app")]
pub fn helpers_config() -> Conf {
    localhost_config([3001, 3002, 3003])
}
