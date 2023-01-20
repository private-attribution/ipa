mod metric_collector;
pub mod playbook;
mod verbosity;

use crate::{net::discovery::Conf, test_fixture::net::localhost_config};
pub use metric_collector::{install_collector, CollectorHandle};
pub use verbosity::Verbosity;

#[must_use]
pub fn helpers_config() -> Conf {
    localhost_config([3001, 3002, 3003])
}
