#![deny(clippy::pedantic, clippy::clone_on_ref_ptr)]
#![allow(clippy::module_name_repetitions)]

use cfg_aliases::cfg_aliases;
use ipa_step::build_gate;
use ipa_step_derive::track_steps;

track_steps!(
    setup_steps:
    helpers::prss_protocol::prss_step @ "src/helpers/prss_step.rs",
    protocol::{
        basics::{
            mul::step,
            step,
            sum_of_product::step,
        },
        boolean::{
            comparison_step,
            fallback_step,
            step,
        },
        context::step,
        ipa_prf::{
            boolean_ops::step,
            prf_sharding::step,
            shuffle::step,
            step,
        },
        modulus_conversion::step,
        step,
    },
);

fn main() {
    setup_steps();
    build_gate::<protocol::step::ProtocolStep>();

    // test is not supported because cfg_aliases is based on
    // https://docs.rs/tectonic_cfg_support macro and that only supports features, target_os, family
    // env, etc.
    // https://docs.rs/tectonic_cfg_support/latest/tectonic_cfg_support/struct.TargetConfiguration.html
    cfg_aliases! {
        descriptive_gate: { not(all(feature = "compact-gate", not(test), not(unit_test))) },
        unit_test: { all(not(feature = "shuttle"), feature = "in-memory-infra") },
        web_test: { all(not(feature = "shuttle"), feature = "real-world-infra") },
    }
}
