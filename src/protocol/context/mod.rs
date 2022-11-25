use crate::ff::Field;
use crate::helpers::messaging::Mesh;
use crate::helpers::Role;
use crate::protocol::mul::SecureMul;
use crate::protocol::prss::{IndexedSharedRandomness, SequentialSharedRandomness};
use crate::protocol::reveal::Reveal;
use crate::protocol::{Step, Substep};
use crate::secret_sharing::SecretSharing;
use std::sync::Arc;

mod malicious;
mod semi_honest;

pub use malicious::MaliciousContext;
pub(super) use malicious::SpecialAccessToMaliciousContext;
pub use semi_honest::SemiHonestContext;

use super::sort::reshare::Reshare;

/// Context used by each helper to perform secure computation. Provides access to shared randomness
/// generator and communication channel.
pub trait Context<F: Field>:
    Clone
    + SecureMul<F, Share = <Self as Context<F>>::Share>
    + Reshare<F, Share = <Self as Context<F>>::Share>
    + Reveal<F, Share = <Self as Context<F>>::Share>
{
    /// Secret sharing type this context supports.
    type Share: SecretSharing<F>;

    /// The role of this context.
    fn role(&self) -> Role;

    /// A unique identifier for this stage of the protocol execution.
    #[must_use]
    fn step(&self) -> &Step;

    /// Make a sub-context.
    /// Note that each invocation of this should use a unique value of `step`.
    #[must_use]
    fn narrow<S: Substep + ?Sized>(&self, step: &S) -> Self;

    /// Get the indexed PRSS instance for this step.  It is safe to call this function
    /// multiple times.
    ///
    /// # Panics
    /// If `prss_rng()` is invoked for the same context, this will panic.  Use of
    /// these two functions are mutually exclusive.
    #[must_use]
    fn prss(&self) -> Arc<IndexedSharedRandomness>;

    /// Get a pair of PRSS-based RNGs.  The first is shared with the helper to the "left",
    /// the second is shared with the helper to the "right".
    ///
    /// # Panics
    /// This method can only be called once.  This is also mutually exclusive with `prss()`.
    /// This will panic if you have previously invoked `prss()`.
    #[must_use]
    fn prss_rng(&self) -> (SequentialSharedRandomness, SequentialSharedRandomness);

    /// Get a set of communications channels to different peers.
    #[must_use]
    fn mesh(&self) -> Mesh<'_, '_>;

    /// Generates a new share of one
    fn share_of_one(&self) -> <Self as Context<F>>::Share;
}
