use crate::{
    helpers::{HelperIdentity, Role, RoleAssignment},
    protocol::Gate,
    sharding::{ShardContext, ShardIndex},
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
pub enum InspectContext {
    ShardMessage {
        /// The helper of this instance.
        helper: HelperIdentity,
        /// Shard sending this stream.
        source: ShardIndex,
        /// Shard that will receive this stream.
        dest: ShardIndex,
        /// Circuit gate this stream is tied to.
        gate: Gate,
    },
    MpcMessage {
        /// The shard of this instance.
        /// This is `None` for non-sharded helpers.
        shard: ShardContext,
        /// Helper sending this stream.
        source: HelperIdentity,
        /// Helper that will receive this stream.
        dest: HelperIdentity,
        /// Circuit gate this stream is tied to.
        gate: Gate,
    },
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
/// This may be used to inspect messages between helpers in a sharded environment, but
/// does not support inspecting messages between shards.
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
        let &InspectContext::MpcMessage {
            shard,
            source: _,
            dest,
            ref gate,
        } = ctx
        else {
            panic!("MaliciousHelper does not support inspecting shard messages");
        };
        let dest = self.role_assignment.role(dest);

        MaliciousHelperContext {
            shard,
            dest,
            gate: gate.clone(),
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
    /// The shard of this instance.
    /// This is `None` for non-sharded helpers.
    pub shard: ShardContext,
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
        match *ctx {
            InspectContext::MpcMessage { source, .. } if source == self.identity => {
                (self.inner)(&self.context(ctx), data);
            }
            _ => {}
        }
    }
}
