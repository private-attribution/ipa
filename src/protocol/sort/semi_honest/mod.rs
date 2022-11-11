use std::fmt::Debug;

use crate::protocol::Step;

pub mod bit_permutation;
mod compose;
mod generate_sort_permutation;
pub mod reshare;
mod secureapplyinv;
mod shuffle;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum SortStep {
    ModulusConversion,
    BitPermutationStep,
    ApplyInv,
    ComposeStep,
}

impl Step for SortStep {}

impl AsRef<str> for SortStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::ModulusConversion => "mod_conv",
            Self::BitPermutationStep => "bit_permute",
            Self::ApplyInv => "apply_inv",
            Self::ComposeStep => "compose",
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
