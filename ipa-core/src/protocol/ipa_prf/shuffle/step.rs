use ipa_step_derive::CompactStep;

// Note: the stream interception tests for malicious shuffles require that the
// `TransferXY` and `TransferC` steps have the same name in `OPRFShuffleStep` and
// `ShardedShuffleStep`.

#[derive(CompactStep)]
pub(crate) enum OPRFShuffleStep {
    SetupKeys,
    ApplyPermutations,
    GenerateAHat,
    GenerateBHat,
    GenerateZ,
    TransferXY, // Transfer of X2 and Y1
    TransferC,  // Exchange of `C_1` and `C_2`
    #[step(child = crate::protocol::boolean::step::EightBitStep)]
    GenerateTags,
    #[step(child = crate::protocol::ipa_prf::shuffle::step::VerifyShuffleStep)]
    VerifyShuffle,
}

#[derive(CompactStep)]
pub(crate) enum VerifyShuffleStep {
    RevealMACKey,
    HashesH3toH1,
    HashH2toH1,
    HashH3toH2,
}

#[derive(CompactStep)]
pub(crate) enum ShardedShuffleStep {
    SetupKeys,
    #[step(child = crate::protocol::boolean::step::EightBitStep)]
    GenerateTags,
    /// Depending on the helper position inside the MPC ring, generate Ã, B̃ or both.
    PseudoRandomTable,
    /// Permute the input according to the PRSS shared between H1 and H2.
    #[step(child = ShardedShufflePermuteStep)]
    Permute12,
    /// Permute the input according to the PRSS shared between H2 and H3.
    #[step(child = ShardedShufflePermuteStep)]
    Permute23,
    /// Permute the input according to the PRSS shared between H3 and H1.
    #[step(child = ShardedShufflePermuteStep)]
    Permute31,
    /// Specific to H1 and H2 interaction - H2 informs H1 about |C|.
    Cardinality,
    /// H1 sends X2 to H2. H2 sends Y1 to H3.
    TransferXY,
    /// H2 and H3 interaction - Exchange `C_1` and `C_2`.
    TransferC,
    #[step(child = crate::protocol::ipa_prf::shuffle::step::VerifyShuffleStep)]
    VerifyShuffle,
}

#[derive(CompactStep)]
pub(crate) enum ShardedShufflePermuteStep {
    /// Apply a mask to the given set of shares. Masking values come from PRSS.
    Mask,
    /// Local per-shard shuffle, where each shard redistributes shares locally according to samples
    /// obtained from PRSS. Does not require Shard or MPC communication.
    LocalShuffle,
}
