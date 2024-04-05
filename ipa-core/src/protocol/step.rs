use std::str::FromStr;

use ipa_step_derive::{CompactGate, CompactStep};

#[derive(CompactStep, CompactGate)]
pub enum ProtocolStep {
    #[step(child = crate::protocol::ipa_prf::step::IpaPrfStep)]
    IpaPrf,
    Multiply,

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
    #[step(child = crate::protocol::basics::step::CheckZeroStep)]
    CheckZero,
    #[step(child = crate::protocol::basics::mul::step::MaliciousMultiplyStep)]
    MaliciousMultiply,
    #[step(child = crate::protocol::basics::mul::step::UpgradeStep)]
    DummyUpgrade,
    #[step(child = crate::protocol::basics::sum_of_product::malicious::step::Step)]
    SumOfProductMalicious,
    #[step(child = crate::protocol::boolean::step::BitwiseLessThanStep)]
    BitwiseLessThan,
    #[step(child = crate::protocol::boolean::step::GreaterThanConstantStep)]
    GreaterThanConstant,
    #[step(child = crate::protocol::boolean::step::ComparisonStep)]
    Comparison,
    #[step(child = crate::protocol::boolean::random_bits_generator::fallback_step::FallbackStep)]
    RandomBitFallback,
    #[step(child = crate::protocol::boolean::step::SolvedBitsStep)]
    SolvedBits,
    #[step(child = crate::protocol::context::step::UpgradeStep)]
    UpgradeShare,
    #[step(child = crate::protocol::context::step::UpgradeTripleStep)]
    UpgradeBitTriple,
    #[step(child = crate::protocol::context::step::MaliciousProtocolStep)]
    MaliciousProtocol,
    #[step(child = crate::protocol::context::step::ValidateStep)]
    MaliciousValidation,
    #[step(child = crate::protocol::ipa_prf::boolean_ops::step::SaturatedAdditionStep)]
    SaturatedAddition,
    #[step(child = crate::protocol::ipa_prf::boolean_ops::step::SaturatedSubtractionStep)]
    SaturatedSubtraction,
    #[step(child = crate::protocol::ipa_prf::prf_sharding::step::FeatureLabelDotProductStep)]
    FeatureLabelDotProduct,
    #[step(child = crate::protocol::modulus_conversion::step::ConvertSharesStep)]
    ConvertShares,
}
