#[test]
fn derive_gate() {
    let t = trybuild::TestCases::new();
    t.pass("tests/derive_gate/state_transition.rs");
    t.compile_fail("tests/derive_gate/missing_step.rs");
    t.compile_fail("tests/derive_gate/not_struct.rs");
}
