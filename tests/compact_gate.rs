// integration tests in this file are run with `--features="enable-bench compact-gate"` which causes
// some pub functions in `common` to be compiled, and rust complains about dead code.
#[allow(dead_code)]
mod common;

use std::num::NonZeroU32;

use common::test_ipa_with_config;
use ipa::{helpers::query::IpaQueryConfig, test_fixture::ipa::IpaSecurityModel};

fn test_compact_gate(
    mode: IpaSecurityModel,
    per_user_credit_cap: u32,
    attribution_window_seconds: u32,
) {
    let mut config = IpaQueryConfig::default();
    config.per_user_credit_cap = per_user_credit_cap;

    if attribution_window_seconds == 0 {
        config.attribution_window_seconds = None;
    } else {
        config.attribution_window_seconds =
            Some(NonZeroU32::new(attribution_window_seconds).unwrap());
    }

    test_ipa_with_config(mode, false, config);
}

#[test]
fn compact_gate_cap_1_no_window_semi_honest() {
    test_compact_gate(IpaSecurityModel::SemiHonest, 1, 0);
}

#[test]
fn compact_gate_cap_1_no_window_malicious() {
    test_compact_gate(IpaSecurityModel::Malicious, 1, 0);
}

#[test]
fn compact_gate_cap_1_with_window_semi_honest() {
    test_compact_gate(IpaSecurityModel::SemiHonest, 1, 86400);
}

#[test]
fn compact_gate_cap_1_with_window_malicious() {
    test_compact_gate(IpaSecurityModel::Malicious, 1, 86400);
}

#[test]
fn compact_gate_cap_10_no_window_semi_honest() {
    test_compact_gate(IpaSecurityModel::SemiHonest, 10, 0);
}

#[test]
fn compact_gate_cap_10_no_window_malicious() {
    test_compact_gate(IpaSecurityModel::Malicious, 10, 0);
}

#[test]
fn compact_gate_cap_10_with_window_semi_honest() {
    test_compact_gate(IpaSecurityModel::SemiHonest, 10, 86400);
}

#[test]
fn compact_gate_cap_10_with_window_malicious() {
    test_compact_gate(IpaSecurityModel::Malicious, 10, 86400);
}
