use super::Share;

/// Trait for binary types used to represent single-bit secret shared values
pub trait Binary: Share + Clone + Eq + PartialEq + Ord + Into<u128> {}

// `bool` implements `Into<u128>`. Rust guarantees `false` and `true` to be `0` and `1` respectively.
impl Binary for bool {}

impl Share for bool {
    const DEFAULT: Self = false;
}
