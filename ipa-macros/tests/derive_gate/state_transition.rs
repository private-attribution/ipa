mod common;

use crate::common::*;
use ipa_macros::Gate;

#[derive(Gate)]
pub struct Compact(pub u16);

fn main() {
    let root = Compact(0);
    assert_eq!("root", root.as_ref());

    let foo = root.narrow(&StepA::Foo);
    assert_eq!("foo", foo.as_ref());

    let foobar = foo.narrow(&StepB::Bar);
    assert_eq!("foo/bar", foobar.as_ref());

    let foobaz = foo.narrow(&StepB::Baz);
    assert_eq!("foo/baz", foobaz.as_ref());
}
