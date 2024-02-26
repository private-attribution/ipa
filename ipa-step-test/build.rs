use complex_step::ComplexStep;
use ipa_step::{build_gate, load_steps, track_steps};

load_steps!(basic_step, complex_step);

fn main() {
    track_steps!(basic_step, complex_step);

    build_gate::<ComplexStep>();
}
