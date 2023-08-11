// integration tests in this file are run with `--features="enable-bench compact-gate"` which causes
// some pub functions in `common` to be compiled, and rust complains about dead code.
#[allow(dead_code)]
mod common;

use std::num::NonZeroU32;

use common::test_ipa_with_config;
use ipa::{helpers::query::IpaQueryConfig, test_fixture::ipa::IpaSecurityModel};

fn test_compact_gate<I: TryInto<NonZeroU32>>(
    mode: IpaSecurityModel,
    per_user_credit_cap: u32,
    attribution_window_seconds: I,
) {
    let config = IpaQueryConfig {
        per_user_credit_cap,
        attribution_window_seconds: attribution_window_seconds.try_into().ok(),
        ..Default::default()
    };

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
