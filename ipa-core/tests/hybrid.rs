// some pub functions in `common` to be compiled, and rust complains about dead code.
#[allow(dead_code)]
mod common;

use std::process::{Command, Stdio};

use common::{tempdir::TempDir, CommandExt, UnwrapStatusExt, TEST_RC_BIN};
use rand::thread_rng;
use rand_core::RngCore;

pub const IN_THE_CLEAR_BIN: &str = env!("CARGO_BIN_EXE_in_the_clear");

// this currently only generates data and runs in the clear
// eventaully we'll want to add the MPC as well
#[test]
fn test_hybrid() {
    const INPUT_SIZE: usize = 100;
    const MAX_CONVERSION_VALUE: usize = 5;
    const MAX_BREAKDOWN_KEY: usize = 20;
    const MAX_CONVS_PER_IMP: usize = 10;

    let dir = TempDir::new_delete_on_drop();

    // Gen inputs
    let input_file = dir.path().join("ipa_inputs.txt");
    let output_file = dir.path().join("ipa_output.json");

    let mut command = Command::new(TEST_RC_BIN);
    command
        .args(["--output-file".as_ref(), input_file.as_os_str()])
        .arg("gen-hybrid-inputs")
        .args(["--count", &INPUT_SIZE.to_string()])
        .args(["--max-conversion-value", &MAX_CONVERSION_VALUE.to_string()])
        .args(["--max-breakdown-key", &MAX_BREAKDOWN_KEY.to_string()])
        .args(["--max-convs-per-imp", &MAX_CONVS_PER_IMP.to_string()])
        .args(["--seed", &thread_rng().next_u64().to_string()])
        .silent()
        .stdin(Stdio::piped());
    command.status().unwrap_status();

    let mut command = Command::new(IN_THE_CLEAR_BIN);
    command
        .args(["--input-file".as_ref(), input_file.as_os_str()])
        .args(["--output-file".as_ref(), output_file.as_os_str()])
        .silent()
        .stdin(Stdio::piped());
    command.status().unwrap_status();
}
