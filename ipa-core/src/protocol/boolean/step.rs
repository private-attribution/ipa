use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
pub enum EightBitStep {
    #[step(count = 8)]
    Bit(usize),
}

impl From<usize> for EightBitStep {
    fn from(v: usize) -> Self {
        Self::Bit(v)
    }
}

#[derive(CompactStep)]
pub enum SixteenBitStep {
    #[step(count = 16)]
    Bit(usize),
}

impl From<usize> for SixteenBitStep {
    fn from(v: usize) -> Self {
        Self::Bit(v)
    }
}

#[derive(CompactStep)]
pub enum ThirtyTwoBitStep {
    #[step(count = 32)]
    Bit(usize),
}

impl From<usize> for ThirtyTwoBitStep {
    fn from(v: usize) -> Self {
        Self::Bit(v)
    }
}

#[derive(CompactStep)]
pub enum TwoHundredFiftySixBitOpStep {
    #[step(count = 256)]
    Bit(usize),
}

impl From<usize> for TwoHundredFiftySixBitOpStep {
    fn from(v: usize) -> Self {
        Self::Bit(v)
    }
}

#[cfg(test)]
#[derive(CompactStep)]
pub enum DefaultBitStep {
    #[step(count = 256)]
    Bit(usize),
}

#[cfg(test)]
impl From<usize> for DefaultBitStep {
    fn from(v: usize) -> Self {
        Self::Bit(v)
    }
}
