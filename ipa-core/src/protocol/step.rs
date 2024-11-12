use std::str::FromStr;

use ipa_step_derive::{CompactGate, CompactStep};

#[derive(CompactStep, CompactGate)]
pub enum ProtocolStep {
    Prss,
    CrossShardPrss,
    #[step(child = crate::protocol::ipa_prf::step::IpaPrfStep)]
    IpaPrf,
    #[step(child = crate::protocol::hybrid::step::HybridStep)]
    Hybrid,
    Multiply,
    PrimeFieldAddition,
    #[step(child = crate::protocol::ipa_prf::shuffle::step::ShardedShuffleStep)]
    ShardedShuffle,
    /// Steps used in unit tests are grouped under this one. Ideally it should be
    /// gated behind test configuration, but it does not work with build.rs that
    /// does not enable any features when creating protocol gate file
    #[step(child = TestExecutionStep)]
    Test,
    /// This step includes all the steps that are currently not linked into a top-level protocol.
    ///
    /// This allows those steps to be compiled. However, any use of them will fail at run time.
    #[step(child = DeadCodeStep)]
    DeadCode,
}

impl<'de> serde::Deserialize<'de> for ProtocolGate {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <&str as serde::Deserialize>::deserialize(deserializer)?;
        Self::from_str(s).map_err(serde::de::Error::custom)
    }
}

#[derive(CompactStep)]
pub enum DeadCodeStep {
    #[step(child = crate::protocol::ipa_prf::boolean_ops::step::SaturatedSubtractionStep)]
    SaturatedSubtraction,
    #[step(child = crate::protocol::ipa_prf::prf_sharding::step::FeatureLabelDotProductStep)]
    FeatureLabelDotProduct,
    #[step(child = crate::protocol::ipa_prf::boolean_ops::step::MultiplicationStep)]
    Multiplication,
}

/// Provides a unique per-iteration context in tests.
#[derive(CompactStep)]
pub enum TestExecutionStep {
    #[step(count = 999)]
    Iter(usize),
}
