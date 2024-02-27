use ipa_step::{build_gate, load_steps, track_steps};

// Here, you list the modules that contain steps.
// These files should only contain steps and nothing else,
// otherwise you will make the build take longer than necessary.
// If they are not in the usual place, or if they are defined in "foo/mod.rs",
// then you will need to list the files too.
load_steps!(basic_step, complex_step @ "src/complex_step.rs");

fn main() {
    // This macro is identical to the one above, except that it generates code.
    track_steps!(basic_step, complex_step @ "src/complex_step.rs");

    // Now, for each step that is annotated with `#[derive(CompactGate)]`,
    // invoke this script to build it.
    build_gate::<complex_step::ComplexStep>();
}

// Note that this process might be made smoother with another macro.
// Unfortunately, building that macro turned out to be rather hard.
