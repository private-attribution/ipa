use std::borrow::Cow;
use std::marker::PhantomData;
use std::sync::Arc;

use super::{
    prss::{IndexedSharedRandomness, SequentialSharedRandomness},
    Step, Substep,
};
use crate::protocol::share_of_one::ShareOfOne;
use crate::{
    ff::Field,
    helpers::{
        messaging::{Gateway, Mesh},
        Role,
    },
    protocol::{malicious::SecurityValidatorAccumulator, prss::Endpoint as PrssEndpoint},
};

use crate::protocol::mul::SecureMul;
use crate::protocol::reveal::Reveal;

use crate::secret_sharing::{MaliciousReplicated, Replicated, SecretSharing};

/// Context used by each helper to perform secure computation. Provides access to shared randomness
/// generator and communication channel.
pub trait ProtocolContext<F: Field>:
    Clone
    + SecureMul<F, Share = <Self as ProtocolContext<F>>::Share>
    + ShareOfOne<F, Share = <Self as ProtocolContext<F>>::Share>
    + Reveal
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
}

/// Contains things that are applicable to any implementation of protocol context as see it today
/// Every context requires access to current step, PRSS and communication and that is what this
/// struct carries.
#[derive(Clone, Debug)]
struct ContextInner<'a> {
    role: Role,
    step: Step,
    prss: &'a PrssEndpoint,
    gateway: &'a Gateway,
}

impl<'a> ContextInner<'a> {
    fn new(role: Role, prss: &'a PrssEndpoint, gateway: &'a Gateway) -> Self {
        Self {
            role,
            step: Step::default(),
            prss,
            gateway,
        }
    }

    fn narrow<S: Substep + ?Sized>(&self, step: &S) -> Self {
        Self {
            role: self.role,
            step: self.step.narrow(step),
            prss: self.prss,
            gateway: self.gateway,
        }
    }
}

/// Context for protocol executions suitable for semi-honest security model, i.e. secure against
/// honest-but-curious adversary parties.
#[derive(Clone, Debug)]
pub struct SemiHonestProtocolContext<'a, F: Field> {
    inner: Cow<'a, ContextInner<'a>>,
    _marker: PhantomData<F>,
}

/// Represents protocol context in malicious setting, i.e. secure against one active adversary
/// in 3 party MPC ring.
#[derive(Clone, Debug)]
pub struct MaliciousProtocolContext<'a, F: Field> {
    inner: Cow<'a, ContextInner<'a>>,
    accumulator: SecurityValidatorAccumulator<F>,
    r_share: Replicated<F>,
}

impl<'a, F: Field> SemiHonestProtocolContext<'a, F> {
    pub fn new(role: Role, participant: &'a PrssEndpoint, gateway: &'a Gateway) -> Self {
        Self {
            inner: Cow::Owned(ContextInner::new(role, participant, gateway)),
            _marker: PhantomData::default(),
        }
    }

    fn from_inner(inner: Cow<'a, ContextInner<'a>>) -> Self {
        Self {
            inner,
            _marker: PhantomData::default(),
        }
    }

    #[must_use]
    pub fn upgrade_to_malicious(
        self,
        accumulator: SecurityValidatorAccumulator<F>,
        r_share: Replicated<F>,
    ) -> MaliciousProtocolContext<'a, F> {
        MaliciousProtocolContext::from_inner(self.inner, accumulator, r_share)
    }
}

impl<'a, F: Field> ProtocolContext<F> for SemiHonestProtocolContext<'a, F> {
    type Share = Replicated<F>;

    fn role(&self) -> Role {
        self.inner.role
    }

    fn step(&self) -> &Step {
        &self.inner.step
    }

    fn narrow<S: Substep + ?Sized>(&self, step: &S) -> Self {
        Self {
            inner: Cow::Owned(self.inner.narrow(step)),
            _marker: PhantomData::default(),
        }
    }

    fn prss(&self) -> Arc<IndexedSharedRandomness> {
        self.inner.prss.indexed(self.step())
    }

    fn prss_rng(&self) -> (SequentialSharedRandomness, SequentialSharedRandomness) {
        self.inner.prss.sequential(self.step())
    }

    fn mesh(&self) -> Mesh<'_, '_> {
        self.inner.gateway.mesh(self.step())
    }
}

impl<'a, F: Field> MaliciousProtocolContext<'a, F> {
    pub fn new(
        role: Role,
        participant: &'a PrssEndpoint,
        gateway: &'a Gateway,
        acc: SecurityValidatorAccumulator<F>,
        r_share: Replicated<F>,
    ) -> Self {
        Self {
            inner: Cow::Owned(ContextInner::new(role, participant, gateway)),
            accumulator: acc,
            r_share,
        }
    }

    fn from_inner(
        inner: Cow<'a, ContextInner<'a>>,
        acc: SecurityValidatorAccumulator<F>,
        r_share: Replicated<F>,
    ) -> Self {
        Self {
            inner,
            accumulator: acc,
            r_share,
        }
    }

    pub fn r_share(&self) -> &Replicated<F> {
        &self.r_share
    }

    pub fn accumulator(&self) -> SecurityValidatorAccumulator<F> {
        self.accumulator.clone()
    }

    /// Sometimes it is required to reinterpret malicious context as semi-honest. Ideally
    /// protocols should be generic over `SecretShare` trait and not requiring this cast and taking
    /// `ProtocolContext<'a, S: SecretShare<F>, F: Field>` as the context. If that is not possible,
    /// this implementation makes it easier to reinterpret the context as semi-honest.
    ///
    /// The context received will be an exact copy of malicious, so it will be tied up to the same step
    /// and prss.
    #[must_use]
    pub fn to_semi_honest(self) -> SemiHonestProtocolContext<'a, F> {
        SemiHonestProtocolContext::from_inner(self.inner)
    }
}

impl<'a, F: Field> ProtocolContext<F> for MaliciousProtocolContext<'a, F> {
    type Share = MaliciousReplicated<F>;

    fn role(&self) -> Role {
        self.inner.role
    }

    fn step(&self) -> &Step {
        &self.inner.step
    }

    fn narrow<S: Substep + ?Sized>(&self, step: &S) -> Self {
        Self {
            inner: Cow::Owned(self.inner.narrow(step)),
            accumulator: self.accumulator.clone(),
            // TODO (alex, mt) - is cloning ok here or we need to Cow it?
            r_share: self.r_share.clone(),
        }
    }

    fn prss(&self) -> Arc<IndexedSharedRandomness> {
        self.inner.prss.indexed(self.step())
    }

    fn prss_rng(&self) -> (SequentialSharedRandomness, SequentialSharedRandomness) {
        self.inner.prss.sequential(self.step())
    }

    fn mesh(&self) -> Mesh<'_, '_> {
        self.inner.gateway.mesh(self.step())
    }
}
