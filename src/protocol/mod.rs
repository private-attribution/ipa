/// Defines a unique step of the IPA protocol. Step is a transformation that occurs on the input
/// from the point when shares are received by the MPC helper to the point when result is produced.
///
/// Steps form a hierarchy where top-level steps describe large building blocks for IPA protocol
/// (such as sort shares, convert shares, apply DP, etc) and bottom-level steps are granular enough
/// to be used to uniquely identify multiplications happening concurrently.
///
/// For example: some modulus conversion protocols require 2*`N` multiplications to convert a XOR share
/// to replicated share (see [paper](https://eprint.iacr.org/2019/695.pdf)). Each multiplication has
/// a unique `ShareConversionStep::X1X2(bit)` or `ShareConversionStep::X1X2X3(bit)` step assigned to it.
///
/// A set of steps define an arithmetic circuit. If IPA needs more than one circuit due to evolution,
/// there will be another layer of indirection in this enum: V1, V2, etc.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ProtocolStep {
    /// Convert from XOR shares to Replicated shares
    ConvertShares(ShareConversionStep),
    /// Sort shares by the match key
    Sort(SortStep),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ShareConversionStep {
    // Compute step x1 ⊕ x2 for i-th bit
    X1X2(u8),
    // Compute step (x1 ⊕ x2) ⊕ x3 for i-th bit
    X1X2X3(u8),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SortStep {}
