use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
pub(crate) enum PaddingDpStep {
    PaddingDp,
    #[step(child = crate::protocol::ipa_prf::oprf_padding::step::SendTotalRows)]
    PaddingDpPass1,
    #[step(child = crate::protocol::ipa_prf::oprf_padding::step::SendTotalRows)]
    PaddingDpPass2,
    #[step(child = crate::protocol::ipa_prf::oprf_padding::step::SendTotalRows)]
    PaddingDpPass3,
}

#[derive(CompactStep)]
pub(crate) enum SendTotalRows {
    SendFakeNumRecords,
}
