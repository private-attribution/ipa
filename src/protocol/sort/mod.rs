pub mod apply_sort;
pub mod bit_permutation;
pub mod generate_permutation;
pub mod generate_permutation_opt;

mod apply;
mod compose;
mod multi_bit_permutation;
mod secureapplyinv;
mod shuffle;

use crate::{protocol::Substep, repeat64str};
use std::fmt::Debug;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum SortStep {
    BitPermutationStep,
    ApplyInv,
    ComposeStep,
    ShuffleRevealPermutation,
    SortKeys,
    MultiApplyInv(u32),
}

impl Substep for SortStep {}

impl AsRef<str> for SortStep {
    fn as_ref(&self) -> &str {
        const MULTI_APPLY_INV: [&str; 64] = repeat64str!["multi_apply_inv"];
        match self {
            Self::BitPermutationStep => "bit_permute",
            Self::ApplyInv => "apply_inv",
            Self::ComposeStep => "compose",
            Self::ShuffleRevealPermutation => "shuffle_reveal_permutation",
            Self::SortKeys => "sort_keys",
            Self::MultiApplyInv(i) => MULTI_APPLY_INV[usize::try_from(*i).unwrap()],
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
    GeneratePermutation,
    RevealPermutation,
    ShufflePermutation,
}

impl Substep for ShuffleRevealStep {}

impl AsRef<str> for ShuffleRevealStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::GeneratePermutation => "generate_permutation",
            Self::RevealPermutation => "reveal_permutation",
            Self::ShufflePermutation => "shuffle_permutation",
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum ReshareStep {
    RandomnessForValidation,
    ReshareRx,
}

impl Substep for ReshareStep {}

impl AsRef<str> for ReshareStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::RandomnessForValidation => "randomness_for_validation",
            Self::ReshareRx => "reshare_rx",
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum MultiBitPermutationStep {
    MultiplyAcrossBits,
}

impl Substep for MultiBitPermutationStep {}

impl AsRef<str> for MultiBitPermutationStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::MultiplyAcrossBits => "multiply_across_bits",
        }
    }
}
