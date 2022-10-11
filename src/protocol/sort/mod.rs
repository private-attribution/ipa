use std::fmt::{Debug, Formatter};

use crate::helpers::prss::SpaceIndex;

use super::Step;

mod apply;
pub mod bit_permutations;
pub mod reshare;
pub mod reveal;
mod shuffle;

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
        0
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
