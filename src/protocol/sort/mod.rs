pub mod bit_permutations;
mod compose;
pub mod reshare;

mod apply;
mod secureapplyinv;
mod shuffle;

use super::Step;

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

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum ApplyInvStep {
    ShuffleInputs,
    ShufflePermutation,
    RevealPermutation,
}

impl Step for ApplyInvStep {}

impl AsRef<str> for ApplyInvStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::ShuffleInputs => "shuffle_inputs",
            Self::ShufflePermutation => "shuffle_permutation",
            Self::RevealPermutation => "reveal_permutation",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ComposeStep {
    ShuffleSigma,
    RevealPermutation,
    UnshuffleRho,
}

impl Step for ComposeStep {}

impl AsRef<str> for ComposeStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::ShuffleSigma => "shuffle_sigma",
            Self::RevealPermutation => "compose_reveal_permutation",
            Self::UnshuffleRho => "unshuffle_rho",
        }
    }
}
