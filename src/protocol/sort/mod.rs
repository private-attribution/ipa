pub mod bit_permutations;
pub mod reshare;

mod apply;
mod shuffle;

use super::Step;
use crate::error::Error;
use std::fmt::{Debug, Display, Formatter};

#[allow(clippy::module_name_repetitions)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum SortStep {
    BitPermutations,
}

impl Step for SortStep {}

impl AsRef<str> for SortStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::BitPermutations => "permute",
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
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

impl AsRef<str> for ShuffleStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::Step1 => "shuffle1",
            Self::Step2 => "shuffle2",
            Self::Step3 => "shuffle3",
        }
    }
}
