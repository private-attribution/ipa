#[allow(dead_code)]
mod common;

use std::num::NonZeroU32;

use common::{test_ipa, test_ipa_with_config};
use ipa_core::{helpers::query::IpaQueryConfig, test_fixture::ipa::IpaSecurityModel};

fn build_config() -> IpaQueryConfig {
    IpaQueryConfig {
        per_user_credit_cap: 8,
        attribution_window_seconds: NonZeroU32::new(0),
        with_dp: 0,
        ..Default::default()
    }
}

#[test]
fn relaxed_dp_semi_honest() {
    let encrypted_input = false;
    let config = build_config();

    test_ipa_with_config::<100>(
        IpaSecurityModel::SemiHonest,
        encrypted_input,
        config,
        encrypted_input,
    );
}

#[test]
fn relaxed_dp_malicious() {
    let encrypted_input = false;
    let config = build_config();

    test_ipa_with_config::<100>(
        IpaSecurityModel::Malicious,
        encrypted_input,
        config,
        encrypted_input,
    );
}

#[test]
#[cfg(all(test, web_test))]
fn relaxed_dp_https_malicious_ipa() {
    test_ipa::<100>(IpaSecurityModel::Malicious, true, true);
}
