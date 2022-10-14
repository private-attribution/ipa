pub mod bit_permutations;
pub mod reshare;

mod apply;
mod shuffle;

use super::Step;
use crate::error::Error;
use crate::helpers::prss::SpaceIndex;
use std::fmt::{Debug, Display, Formatter};

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SortStep {
    BitPermutations,
}

impl SortStep {
    const BIT_PERMUTATIONS_STR: &'static str = "bit-permutations";
}

impl Display for SortStep {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BitPermutations => write!(f, "{}", Self::BIT_PERMUTATIONS_STR),
        }
    }
}

impl TryFrom<String> for SortStep {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let value = value.strip_prefix('/').unwrap_or(&value).to_lowercase();
        match value.as_str() {
            Self::BIT_PERMUTATIONS_STR => Ok(Self::BitPermutations),
            _ => Err(Error::path_parse_error(&value)),
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

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ShuffleStep {
    Step1,
    Step2,
    Step3,
}

impl ShuffleStep {
    const STEP1_STR: &'static str = "step1";
    const STEP2_STR: &'static str = "step2";
    const STEP3_STR: &'static str = "step3";
}

impl Display for ShuffleStep {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ShuffleStep::Step1 => write!(f, "{}", Self::STEP1_STR),
            ShuffleStep::Step2 => write!(f, "{}", Self::STEP2_STR),
            ShuffleStep::Step3 => write!(f, "{}", Self::STEP3_STR),
        }
    }
}

impl TryFrom<String> for ShuffleStep {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            Self::STEP1_STR => Ok(Self::Step1),
            Self::STEP2_STR => Ok(Self::Step2),
            Self::STEP3_STR => Ok(Self::Step3),
            other => Err(Error::path_parse_error(other)),
        }
    }
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
