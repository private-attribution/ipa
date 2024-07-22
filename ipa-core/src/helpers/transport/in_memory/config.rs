use std::borrow::Cow;

use crate::{
    helpers::{HelperIdentity, Role, RoleAssignment},
    protocol::Gate,
    sharding::ShardIndex,
    sync::Arc,
};

pub type DynStreamInterceptor = Arc<dyn StreamInterceptor<Context = InspectContext>>;

/// The interface for stream interceptors.
///
/// It is used in test infrastructure to inspect
/// incoming streams and perform actions based on
/// their contents.
///
/// The `peek` method takes a context object and a mutable reference
/// to the data buffer. It is responsible for inspecting the data
/// and performing any necessary actions based on the context.
pub trait StreamInterceptor: Send + Sync {
    /// The context type for the stream peeker.
    /// See [`InspectContext`] and [`MaliciousHelperContext`] for
    /// details.
    type Context;

    /// Inspects the stream data and performs any necessary actions.
    /// The `data` buffer may be modified in-place.
    ///
    /// ## Implementation considerations
    /// This method is free to mutate the `data` buffer
    /// however it wants, but it needs to account for the following:
    ///
    /// ### Prime field streams
    /// Corrupting streams that send data as sequences of serialized
    /// [`PrimeField`] may cause `GreaterThanPrimeError` errors at
    /// the serialization layer, instead of maybe intended malicious
    /// validation failures.
    ///
    /// ### Boolean fields
    /// Flipping bits in fixed-size bit strings is indistinguishable
    /// from additive attacks without additional measures implemented
    /// at the transport layer, like checksumming, share consistency
    /// checks, etc.
    fn peek(&self, ctx: &Self::Context, data: &mut Vec<u8>);
}

impl<F: Fn(&InspectContext, &mut Vec<u8>) + Send + Sync + 'static> StreamInterceptor for F {
    type Context = InspectContext;

    fn peek(&self, ctx: &Self::Context, data: &mut Vec<u8>) {
        (self)(ctx, data);
    }
}

/// The general context provided to stream inspectors.
#[derive(Debug)]
pub struct InspectContext {
    /// The shard index of this instance.
    /// This is `None` for non-sharded helpers.
    pub shard_index: Option<ShardIndex>,
    /// The MPC identity of this instance.
    /// The combination (`shard_index`, `identity`)
    /// uniquely identifies a single shard within
    /// a multi-sharded MPC system.
    pub identity: HelperIdentity,
    /// Helper that will receive this stream.
    pub dest: Cow<'static, str>,
    /// Circuit gate this stream is tied to.
    pub gate: Gate,
}

/// The no-op stream peeker, which does nothing.
/// This is used as a default value for stream
/// peekers that don't do anything.
#[inline]
#[must_use]
pub fn passthrough() -> Arc<dyn StreamInterceptor<Context = InspectContext>> {
    Arc::new(|_ctx: &InspectContext, _data: &mut Vec<u8>| {})
}

/// This narrows the implementation of stream seeker
/// to a specific helper role. Only streams sent from
/// that helper will be inspected by the provided closure.
/// Other helper's streams will be left untouched.
///
/// It does not support sharded environments and will panic
/// if used in a sharded test infrastructure.
#[derive(Debug)]
pub struct MaliciousHelper<F> {
    identity: HelperIdentity,
    role_assignment: RoleAssignment,
    inner: F,
}

impl<F: Fn(&MaliciousHelperContext, &mut Vec<u8>) + Send + Sync> MaliciousHelper<F> {
    pub fn new(role: Role, role_assignment: &RoleAssignment, peeker: F) -> Arc<Self> {
        Arc::new(Self {
            identity: role_assignment.identity(role),
            role_assignment: role_assignment.clone(),
            inner: peeker,
        })
    }

    fn context(&self, ctx: &InspectContext) -> MaliciousHelperContext {
        let dest = HelperIdentity::try_from(ctx.dest.as_ref()).unwrap_or_else(|_| {
            panic!(
                "MaliciousServerContext::from: invalid destination: {}",
                ctx.dest
            )
        });
        let dest = self.role_assignment.role(dest);

        MaliciousHelperContext {
            shard_index: ctx.shard_index,
            dest,
            gate: ctx.gate.clone(),
        }
    }
}

/// Special contexts for stream inspectors
/// created with [`MaliciousHelper`].
/// It provides convenient access to the
/// destination role and assumes a single MPC
/// helper intercepting streams.
#[derive(Debug)]
pub struct MaliciousHelperContext {
    /// The shard index of this instance.
    /// This is `None` for non-sharded helpers.
    pub shard_index: Option<ShardIndex>,
    /// Helper that will receive this stream.
    pub dest: Role,
    /// Circuit gate this stream is tied to.
    pub gate: Gate,
}

impl<F: Fn(&MaliciousHelperContext, &mut Vec<u8>) + Send + Sync> StreamInterceptor
    for MaliciousHelper<F>
{
    type Context = InspectContext;

    fn peek(&self, ctx: &Self::Context, data: &mut Vec<u8>) {
        if ctx.identity == self.identity {
            (self.inner)(&self.context(ctx), data);
        }
    }
}
