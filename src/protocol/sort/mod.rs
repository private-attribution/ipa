pub mod bit_permutations;
mod compose;
mod generate_sort_permutations;
pub mod reshare;

mod apply;
mod secureapplyinv;
mod shuffle;

use super::Step;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum SortStep {
    ModulusConversion(u8),
    BitPermutation(u8),
    ApplyInv(u8),
    ComposeStep(u8),
}

impl Step for SortStep {}

impl AsRef<str> for SortStep {
    fn as_ref(&self) -> &str {
        const MODULUSCONVERSION: [&str; 64] = [
            "mc0", "mc1", "mc2", "mc3", "mc4", "mc5", "mc6", "mc7", "mc8", "mc9", "mc10", "mc11",
            "mc12", "mc13", "mc14", "mc15", "mc16", "mc17", "mc18", "mc19", "mc20", "mc21", "mc22",
            "mc23", "mc24", "mc25", "mc26", "mc27", "mc28", "mc29", "mc30", "mc31", "mc32", "mc33",
            "mc34", "mc35", "mc36", "mc37", "mc38", "mc39", "mc40", "mc41", "mc42", "mc43", "mc44",
            "mc45", "mc46", "mc47", "mc48", "mc49", "mc50", "mc51", "mc52", "mc53", "mc54", "mc55",
            "mc56", "mc57", "mc58", "mc59", "mc60", "mc61", "mc62", "mc63",
        ];
        const BITPERMUTATIONS: [&str; 64] = [
            "bp0", "bp1", "bp2", "bp3", "bp4", "bp5", "bp6", "bp7", "bp8", "bp9", "bp10", "bp11",
            "bp12", "bp13", "bp14", "bp15", "bp16", "bp17", "bp18", "bp19", "bp20", "bp21", "bp22",
            "bp23", "bp24", "bp25", "bp26", "bp27", "bp28", "bp29", "bp30", "bp31", "bp32", "bp33",
            "bp34", "bp35", "bp36", "bp37", "bp38", "bp39", "bp40", "bp41", "bp42", "bp43", "bp44",
            "bp45", "bp46", "bp47", "bp48", "bp49", "bp50", "bp51", "bp52", "bp53", "bp54", "bp55",
            "bp56", "bp57", "bp58", "bp59", "bp60", "bp61", "bp62", "bp63",
        ];

        const APPLYINV: [&str; 64] = [
            "ai0", "ai1", "ai2", "ai3", "ai4", "ai5", "ai6", "ai7", "ai8", "ai9", "ai10", "ai11",
            "ai12", "ai13", "ai14", "ai15", "ai16", "ai17", "ai18", "ai19", "ai20", "ai21", "ai22",
            "ai23", "ai24", "ai25", "ai26", "ai27", "ai28", "ai29", "ai30", "ai31", "ai32", "ai33",
            "ai34", "ai35", "ai36", "ai37", "ai38", "ai39", "ai40", "ai41", "ai42", "ai43", "ai44",
            "ai45", "ai46", "ai47", "ai48", "ai49", "ai50", "ai51", "ai52", "ai53", "ai54", "ai55",
            "ai56", "ai57", "ai58", "ai59", "ai60", "ai61", "ai62", "ai63",
        ];

        const COMPOSE: [&str; 64] = [
            "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "c10", "c11", "c12", "c13",
            "c14", "c15", "c16", "c17", "c18", "c19", "c20", "c21", "c22", "c23", "c24", "c25",
            "c26", "c27", "c28", "c29", "c30", "c31", "c32", "c33", "c34", "c35", "c36", "c37",
            "c38", "c39", "c40", "c41", "c42", "c43", "c44", "c45", "c46", "c47", "c48", "c49",
            "c50", "c51", "c52", "c53", "c54", "c55", "c56", "c57", "c58", "c59", "c60", "c61",
            "c62", "c63",
        ];
        match self {
            Self::ModulusConversion(i) => MODULUSCONVERSION[usize::from(*i)],
            Self::BitPermutation(i) => BITPERMUTATIONS[usize::from(*i)],
            Self::ApplyInv(i) => APPLYINV[usize::from(*i)],
            Self::ComposeStep(i) => COMPOSE[usize::from(*i)],
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
