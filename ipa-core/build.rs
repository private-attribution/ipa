use cfg_aliases::cfg_aliases;

fn main() {
    // test is not supported because cfg_aliases is based on
    // https://docs.rs/tectonic_cfg_support macro and that only supports features, target_os, family
    // env, etc.
    // https://docs.rs/tectonic_cfg_support/latest/tectonic_cfg_support/struct.TargetConfiguration.html
    cfg_aliases! {
        unit_test: { all(not(feature = "shuttle"), not(feature = "compact-gate"), feature = "in-memory-infra") },
        web_test: { all(not(feature = "shuttle"), not(feature = "compact-gate"), feature = "real-world-infra") },
    }
}
