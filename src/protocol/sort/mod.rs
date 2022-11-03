use super::Step;
use std::fmt::Debug;

mod apply;
pub mod bit_permutation;
mod compose;
mod generate_sort_permutation;
pub mod reshare;
mod secureapplyinv;
mod shuffle;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum SortStep {
    ModulusConversion(usize),
    BitPermutationStep,
    ApplyInv,
    ComposeStep,
}

impl Step for SortStep {}

impl AsRef<str> for SortStep {
    fn as_ref(&self) -> &str {
        //TODO : This needs to go away and modulus conversion should be able to work without passing a step per record ID.
        // Also, this is incorrect since it works for only 64 inputs and not usize
        const MODULUSCONVERSION: [&str; 64] = [
            "mc0", "mc1", "mc2", "mc3", "mc4", "mc5", "mc6", "mc7", "mc8", "mc9", "mc10", "mc11",
            "mc12", "mc13", "mc14", "mc15", "mc16", "mc17", "mc18", "mc19", "mc20", "mc21", "mc22",
            "mc23", "mc24", "mc25", "mc26", "mc27", "mc28", "mc29", "mc30", "mc31", "mc32", "mc33",
            "mc34", "mc35", "mc36", "mc37", "mc38", "mc39", "mc40", "mc41", "mc42", "mc43", "mc44",
            "mc45", "mc46", "mc47", "mc48", "mc49", "mc50", "mc51", "mc52", "mc53", "mc54", "mc55",
            "mc56", "mc57", "mc58", "mc59", "mc60", "mc61", "mc62", "mc63",
        ];
        match self {
            Self::ModulusConversion(i) => MODULUSCONVERSION[*i],
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
