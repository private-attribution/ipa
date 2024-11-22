pub mod lagrange;
pub mod prover;
pub mod verifier;

pub type FirstProofGenerator = prover::SmallProofGenerator;
pub type CompressedProofGenerator = prover::SmallProofGenerator;
pub use lagrange::{CanonicalLagrangeDenominator, LagrangeTable};
pub use prover::ProverTableIndices;
pub use verifier::VerifierTableIndices;

pub const FIRST_RECURSION_FACTOR: usize = FirstProofGenerator::RECURSION_FACTOR;
