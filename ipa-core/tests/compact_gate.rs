// integration tests in this file are run with `--features="enable-bench compact-gate"` which causes
// some pub functions in `common` to be compiled, and rust complains about dead code.
#[allow(dead_code)]
mod common;

use std::num::NonZeroU32;

use common::test_ipa_with_config;
use ipa_core::{helpers::query::IpaQueryConfig, test_fixture::ipa::IpaSecurityModel};

fn test_compact_gate<I: TryInto<NonZeroU32>>(
    mode: IpaSecurityModel,
    per_user_credit_cap: u32,
    attribution_window_seconds: I,
    encrypted_input: bool,
) {
    let config = IpaQueryConfig {
        per_user_credit_cap,
        attribution_window_seconds: attribution_window_seconds.try_into().ok(),
        with_dp: 0,
        ..Default::default()
    };

    // test https with encrypted input
    // and http with plaintest input
    test_ipa_with_config(mode, encrypted_input, config, encrypted_input);
}

#[test]
fn compact_gate_cap_8_no_window_semi_honest_encryped_input() {
    test_compact_gate(IpaSecurityModel::SemiHonest, 8, 0, true);
}

#[test]
fn compact_gate_cap_1_no_window_semi_honest_encryped_input() {
    test_compact_gate(IpaSecurityModel::SemiHonest, 1, 0, true);
}

#[test]
fn compact_gate_cap_2_no_window_semi_honest_encryped_input() {
    test_compact_gate(IpaSecurityModel::SemiHonest, 2, 0, true);
}

#[test]
fn compact_gate_cap_3_no_window_semi_honest_encryped_input() {
    test_compact_gate(IpaSecurityModel::SemiHonest, 3, 0, true);
}

#[test]
fn compact_gate_cap_4_no_window_semi_honest_encryped_input() {
    test_compact_gate(IpaSecurityModel::SemiHonest, 4, 0, true);
}

#[test]
fn compact_gate_cap_8_no_window_semi_honest_plaintext_input() {
    test_compact_gate(IpaSecurityModel::SemiHonest, 8, 0, false);
}

#[test]
/// This test is turned off because of [`issue`].
///
/// This test will hang without `relaxed-dp` feature turned out until it is fixed
/// [`issue`]: https://github.com/private-attribution/ipa/issues/1298
#[ignore]
fn compact_gate_cap_8_no_window_malicious_encrypted_input() {
    test_compact_gate(IpaSecurityModel::Malicious, 8, 0, true);
}

#[test]
/// This test is turned off because of [`issue`].
///
/// This test will hang without `relaxed-dp` feature turned out until it is fixed
/// [`issue`]: https://github.com/private-attribution/ipa/issues/1298
#[ignore]
fn compact_gate_cap_8_no_window_malicious_plaintext_input() {
    test_compact_gate(IpaSecurityModel::Malicious, 8, 0, false);
}

#[test]
fn compact_gate_cap_8_with_window_semi_honest_encryped_input() {
    test_compact_gate(IpaSecurityModel::SemiHonest, 8, 86400, true);
}

#[test]
fn compact_gate_cap_8_with_window_semi_honest_plaintext_input() {
    test_compact_gate(IpaSecurityModel::SemiHonest, 8, 86400, false);
}

#[test]
fn compact_gate_cap_16_no_window_semi_honest_encryped_input() {
    test_compact_gate(IpaSecurityModel::SemiHonest, 16, 0, true);
}

#[test]
fn compact_gate_cap_16_no_window_semi_honest_plaintext_input() {
    test_compact_gate(IpaSecurityModel::SemiHonest, 16, 0, false);
}

#[test]
fn compact_gate_cap_16_with_window_semi_honest_encryped_input() {
    test_compact_gate(IpaSecurityModel::SemiHonest, 16, 86400, true);
}

#[test]
fn compact_gate_cap_16_with_window_semi_honest_plaintext_input() {
    test_compact_gate(IpaSecurityModel::SemiHonest, 16, 86400, false);
}
