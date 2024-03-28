use ipa_step::build_gate;
use ipa_step_derive::track_steps;

// Here, you list the modules that contain steps.
// These files should only contain steps and nothing else,
// otherwise you will make the build take longer than necessary.
// If they are not in the usual place, or if they are defined in "foo/mod.rs",
// then you will need to list the files too.
track_steps!(setup: basic_step, complex_step @ "src/complex_step.rs", module::{a, b});

fn main() {
    setup();

    // Now, for each step that is annotated with `#[derive(CompactGate)]`,
    // invoke this script to build it.
    build_gate::<complex_step::ComplexStep>();
    build_gate::<module::a::Alpha>();
}
