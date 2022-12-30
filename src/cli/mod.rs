mod metric_collector;
pub mod playbook;
mod verbosity;

use crate::helpers::transport::http::discovery::conf::Conf;
use crate::test_fixture::net::localhost_config_map;
pub use metric_collector::{install_collector, CollectorHandle};
pub use verbosity::Verbosity;

pub fn helpers_config() -> Conf {
    localhost_config_map([3001, 3002, 3003])
}
