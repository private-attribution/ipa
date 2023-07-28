mod common;

// this import is missing StepB which causes the error
use crate::common::{
    static_deserialize_state_map, static_reverse_state_map, static_state_map, Step, StepA,
    StepNarrow,
};
use ipa_macros::Gate;

#[derive(Gate)]
struct Compact(u16);

fn main() {
    let root = Compact(0);
    assert_eq!("root", root.as_ref());
}
