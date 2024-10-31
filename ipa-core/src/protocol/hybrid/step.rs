use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
pub(crate) enum HybridStep {
    ReshardByTag,
    #[step(child = crate::protocol::ipa_prf::oprf_padding::step::PaddingDpStep, name="padding_dp")]
    PaddingDp,
}
