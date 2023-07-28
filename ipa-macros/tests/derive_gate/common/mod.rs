pub trait Step {}
pub trait StepNarrow<S: Step> {
    #[must_use]
    fn narrow(&self, step: &S) -> Self;
}

pub enum StepA {
    Foo,
    ThisStateDoesNotExistInTheMap,
}
pub enum StepB {
    Bar,
    Baz,
}

impl Step for StepA {}
impl AsRef<str> for StepA {
    fn as_ref(&self) -> &str {
        match self {
            Self::Foo => "foo",
            Self::ThisStateDoesNotExistInTheMap => "this-state-does-not-exist-in-the-map",
        }
    }
}
impl Step for StepB {}
impl AsRef<str> for StepB {
    fn as_ref(&self) -> &str {
        match self {
            Self::Bar => "bar",
            Self::Baz => "baz",
        }
    }
}

pub fn static_state_map(_state: u16, _step: &str) -> u16 {
    unreachable!("static_state_map should not be called")
}

pub fn static_reverse_state_map(state: u16) -> &'static str {
    match state {
        0 => "root",
        _ => unreachable!("static_reverse_state_map should not be called"),
    }
}

pub fn static_deserialize_state_map(s: &str) -> u16 {
    match s {
        "root" => 0,
        _ => unreachable!("static_deserialize_state_map should not be called"),
    }
}
