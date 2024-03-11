use cfg_aliases::cfg_aliases;
use ipa_step::{build_gate, load_steps, track_steps};

load_steps!(helpers::prss_protocol::prss_step @"src/helpers/prss_step.rs");

fn main() {
    track_steps!(helpers::prss_protocol::prss_step @"src/helpers/prss_step.rs");

    build_gate::<helpers::prss_protocol::prss_step::PrssExchangeStep>();

    // test is not supported because cfg_aliases is based on
    // https://docs.rs/tectonic_cfg_support macro and that only supports features, target_os, family
    // env, etc.
    // https://docs.rs/tectonic_cfg_support/latest/tectonic_cfg_support/struct.TargetConfiguration.html
    cfg_aliases! {
        unit_test: { all(not(feature = "shuttle"), feature = "in-memory-infra") },
        web_test: { all(not(feature = "shuttle"), feature = "real-world-infra") },
    }
}
