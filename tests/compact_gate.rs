use std::process::Command;

#[test]
fn compact_gate() {
    let test_script = env!("CARGO_MANIFEST_DIR").to_string() + "/scripts/test_compact_gate.py";
    let mut command = Command::new(test_script);
    command
        .status()
        .expect("Failed to run test_compact_gate.py");
}
