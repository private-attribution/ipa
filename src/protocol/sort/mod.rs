use super::Substep;
use std::fmt::Debug;

mod apply;
pub mod bit_permutation;
mod compose;
pub mod generate_sort_permutation;
pub mod reshare;
mod secureapplyinv;
mod shuffle;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum SortStep {
    ModulusConversion,
    BitPermutationStep,
    ApplyInv,
    ComposeStep,
    ShuffleRevealPermutation,
}

impl Substep for SortStep {}

impl AsRef<str> for SortStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::ModulusConversion => "mod_conv",
            Self::BitPermutationStep => "bit_permute",
            Self::ApplyInv => "apply_inv",
            Self::ComposeStep => "compose",
            Self::ShuffleRevealPermutation => "shuffle_reveal_permutation",
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum ShuffleStep {
    Step1,
    Step2,
    Step3,
}

impl Substep for ShuffleStep {}

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
}

impl Substep for ApplyInvStep {}

impl AsRef<str> for ApplyInvStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::ShuffleInputs => "shuffle_inputs",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ComposeStep {
    UnshuffleRho,
}

impl Substep for ComposeStep {}

impl AsRef<str> for ComposeStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::UnshuffleRho => "unshuffle_rho",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ShuffleRevealStep {
    RevealPermutation,
    ShufflePermutation,
}

impl Substep for ShuffleRevealStep {}

impl AsRef<str> for ShuffleRevealStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::RevealPermutation => "reveal_permutation",
            Self::ShufflePermutation => "shuffle_permutation",
        }
    }
}
