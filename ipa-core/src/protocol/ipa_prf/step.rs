use ipa_step_derive::CompactStep;


#[derive(CompactStep)]
pub(crate) enum PrfStep {
    GenRandomMask,
    #[step(child = crate::protocol::context::step::UpgradeStep)]
    UpgradeY,
    #[step(child = crate::protocol::context::step::UpgradeStep)]
    UpgradeMask,
    #[step(child = crate::protocol::basics::mul::step::MaliciousMultiplyStep)]
    MultMaskWithPRFInput,
    RevealR,
    Revealz,
}
