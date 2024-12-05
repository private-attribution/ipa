// some pub functions in `common` to be compiled, and rust complains about dead code.
#[allow(dead_code)]
mod common;

use std::process::{Command, Stdio};

use common::{
    spawn_shards, tempdir::TempDir, test_sharded_setup, CommandExt, TerminateOnDropExt,
    UnwrapStatusExt, CRYPTO_UTIL_BIN, TEST_RC_BIN,
};
use ipa_core::{cli::playbook::HybridQueryResult, helpers::query::HybridQueryParams};
use rand::thread_rng;
use rand_core::RngCore;

pub const IN_THE_CLEAR_BIN: &str = env!("CARGO_BIN_EXE_in_the_clear");

// this currently only generates data and runs in the clear
// eventaully we'll want to add the MPC as well
#[test]
fn test_hybrid() {
    const INPUT_SIZE: usize = 100;
    const SHARDS: usize = 5;
    const MAX_CONVERSION_VALUE: usize = 5;

    let config = HybridQueryParams {
        max_breakdown_key: 5,
        with_dp: 0,
        epsilon: 0.0,
        plaintext_match_keys: false, // this shouldn't be necessary
    };

    let dir = TempDir::new_delete_on_drop();

    // Gen inputs
    let input_file = dir.path().join("ipa_inputs.txt");
    let in_the_clear_output_file = dir.path().join("ipa_output_in_the_clear.json");
    let output_file = dir.path().join("ipa_output.json");

    let mut command = Command::new(TEST_RC_BIN);
    command
        .args(["--output-file".as_ref(), input_file.as_os_str()])
        .arg("gen-hybrid-inputs")
        .args(["--count", &INPUT_SIZE.to_string()])
        .args(["--max-conversion-value", &MAX_CONVERSION_VALUE.to_string()])
        .args(["--max-breakdown-key", &config.max_breakdown_key.to_string()])
        .args(["--seed", &thread_rng().next_u64().to_string()])
        .silent()
        .stdin(Stdio::piped());
    command.status().unwrap_status();

    let mut command = Command::new(IN_THE_CLEAR_BIN);
    command
        .args(["--input-file".as_ref(), input_file.as_os_str()])
        .args([
            "--output-file".as_ref(),
            in_the_clear_output_file.as_os_str(),
        ])
        .silent()
        .stdin(Stdio::piped());
    command.status().unwrap_status();

    let dir = TempDir::new_delete_on_drop();
    let path = dir.path();

    let sockets = test_sharded_setup::<SHARDS>(path);
    let _helpers = spawn_shards(path, &sockets, true);

    // encrypt input
    let mut command = Command::new(CRYPTO_UTIL_BIN);
    command
        .arg("hybrid-encrypt")
        .args(["--input-file".as_ref(), input_file.as_os_str()])
        .args(["--output-dir".as_ref(), path.as_os_str()])
        .args(["--network".into(), dir.path().join("network.toml")])
        .stdin(Stdio::piped());
    command.status().unwrap_status();
    let enc1 = dir.path().join("helper1.enc");
    let enc2 = dir.path().join("helper2.enc");
    let enc3 = dir.path().join("helper3.enc");

    // Run Hybrid
    let mut command = Command::new(TEST_RC_BIN);
    command
        .args(["--network".into(), dir.path().join("network.toml")])
        .args(["--output-file".as_ref(), output_file.as_os_str()])
        .args(["--shard-count", SHARDS.to_string().as_str()])
        .args(["--wait", "2"])
        .arg("malicious-hybrid")
        .args(["--enc-input-file1".as_ref(), enc1.as_os_str()])
        .args(["--enc-input-file2".as_ref(), enc2.as_os_str()])
        .args(["--enc-input-file3".as_ref(), enc3.as_os_str()])
        .args(["--max-breakdown-key", &config.max_breakdown_key.to_string()]);

    match config.with_dp {
        0 => {
            command.args(["--with-dp", &config.with_dp.to_string()]);
        }
        _ => {
            command
                .args(["--with-dp", &config.with_dp.to_string()])
                .args(["--epsilon", &config.epsilon.to_string()]);
        }
    }
    command.stdin(Stdio::piped());

    let _test_mpc = command.spawn().unwrap().terminate_on_drop();

    // basic output checks - output should have the exact size as number of breakdowns
    let output = serde_json::from_str::<HybridQueryResult>(
        &std::fs::read_to_string(&output_file).expect("IPA results file should exist"),
    )
    .expect("IPA results file is valid JSON");

    assert_eq!(
        usize::try_from(config.max_breakdown_key).unwrap(),
        output.breakdowns.len(),
        "Number of breakdowns does not match the expected",
    );
    assert_eq!(INPUT_SIZE, usize::from(output.input_size));

    // TODO compare in the clear results with MPC results
}
