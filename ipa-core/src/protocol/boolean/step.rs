use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
pub enum BitOpStep {
    #[step(count = 512)]
    Bit(usize),
}

impl From<i32> for BitOpStep {
    fn from(v: i32) -> Self {
        Self::Bit(usize::try_from(v).unwrap())
    }
}

impl From<u32> for BitOpStep {
    fn from(v: u32) -> Self {
        Self::Bit(usize::try_from(v).unwrap())
    }
}

impl From<usize> for BitOpStep {
    fn from(v: usize) -> Self {
        Self::Bit(v)
    }
}

#[derive(CompactStep)]
pub(crate) enum SolvedBitsStep {
    RandomBits,
    IsPLessThanB,
    RevealC,
}

#[derive(CompactStep)]
pub(crate) enum ComparisonStep {
    PrefixOr,
    DotProduct,
}
