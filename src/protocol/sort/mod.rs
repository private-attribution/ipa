use std::fmt::{Debug, Formatter};

use crate::helpers::prss::SpaceIndex;

use super::Step;

mod apply;
pub mod bit_permutations;
pub mod reshare;
pub mod reveal;
mod secureapplyinv;
mod shuffle;

fn concat_two_ipa_steps<A, B, C, G, F>(f: F, g: G) -> impl Fn(A) -> C
where
    F: Fn(A) -> B,
    G: Fn(B) -> C,
{
    move |x| g(f(x))
}

macro_rules! compose_ipa_step {
    ( $last:expr ) => { $last };
    ( $head:expr, $($tail:expr), +) => {
        concat_two_ipa_steps($head, compose_ipa_step!($($tail),+))
    };
}

pub(crate) use compose_ipa_step;

#[allow(clippy::module_name_repetitions)]
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum SortStep {
    BitPermutations,
}

impl Debug for SortStep {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SortStep::BitPermutations => write!(f, "BitPermutations"),
        }
    }
}

impl Step for SortStep {}

impl SpaceIndex for SortStep {
    const MAX: usize = 1;

    fn as_usize(&self) -> usize {
        match self {
            Self::BitPermutations => 0,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum ShuffleStep {
    Step1,
    Step2,
    Step3,
}

impl Step for ShuffleStep {}

impl SpaceIndex for ShuffleStep {
    const MAX: usize = 3;

    fn as_usize(&self) -> usize {
        match self {
            Self::Step1 => 0,
            Self::Step2 => 1,
            Self::Step3 => 2,
        }
    }
}

impl Debug for ShuffleStep {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ShuffleStep::Step1 => write!(f, "Step1"),
            ShuffleStep::Step2 => write!(f, "Step2"),
            ShuffleStep::Step3 => write!(f, "Step3"),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum ApplyInvStep {
    GenerateRandomPermutation,
    ShuffleInputs(ShuffleStep),
    ShufflePermutation(ShuffleStep),
    RevealPermutation,
}

impl Debug for ApplyInvStep {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplyInvStep::ShuffleInputs(v) => write!(f, "ShuffleInputs[{:?}]", v),
            ApplyInvStep::ShufflePermutation(v) => write!(f, "ShufflePermutation[{:?}]", v),
            ApplyInvStep::RevealPermutation => write!(f, "RevealPermutation"),
            ApplyInvStep::GenerateRandomPermutation => write!(f, "GenerateRandomPermutation"),
        }
    }
}

impl Step for ApplyInvStep {}

impl SpaceIndex for ApplyInvStep {
    const MAX: usize = 4;
    fn as_usize(&self) -> usize {
        match self {
            Self::ShuffleInputs(_) => 0,
            Self::ShufflePermutation(_) => 1,
            Self::RevealPermutation => 2,
            Self::GenerateRandomPermutation => 3,
        }
    }
}
