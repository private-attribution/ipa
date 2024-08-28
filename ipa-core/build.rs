#![deny(clippy::pedantic, clippy::clone_on_ref_ptr)]
#![allow(clippy::module_name_repetitions)]

use cfg_aliases::cfg_aliases;
use ipa_step::build_gate;
use ipa_step_derive::track_steps;

track_steps!(
    setup_steps:
    protocol::{
        basics::{
            mul::step,
            step,
        },
        boolean::{
            step,
        },
        context::step,
        ipa_prf::{
            boolean_ops::step,
            prf_sharding::step,
            shuffle::step,
            aggregation::step,
            oprf_padding::step,
            step,
        },
        dp::step,
        step,
    },
    test_fixture::step
);

fn main() {
    if cfg!(feature = "compact-gate") {
        // include protocol_gate.rs. This slows down the build significantly, so avoid doing that
        // in dev builds.
        setup_steps();
        build_gate::<protocol::step::ProtocolStep>();
    }

    // test is not supported because cfg_aliases is based on
    // https://docs.rs/tectonic_cfg_support macro and that only supports features, target_os, family
    // env, etc.
    // https://docs.rs/tectonic_cfg_support/latest/tectonic_cfg_support/struct.TargetConfiguration.html
    cfg_aliases! {
        compact_gate: { feature = "compact-gate" },
        descriptive_gate: { not(compact_gate) },
        unit_test: { all(not(feature = "shuttle"), feature = "in-memory-infra", descriptive_gate) },
        web_test: { all(not(feature = "shuttle"), feature = "real-world-infra") },
    }
    println!("cargo::rustc-check-cfg=cfg(descriptive_gate)");
    println!("cargo::rustc-check-cfg=cfg(compact_gate)");
    println!("cargo::rustc-check-cfg=cfg(unit_test)");
    println!("cargo::rustc-check-cfg=cfg(web_test)");
    println!("cargo::rustc-check-cfg=cfg(coverage)");
}
