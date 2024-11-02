//! IPA infrastructure
//!
//! `infra` would be a more appropriate name for this module. Although some generic utilities are
//! here for historial reasons, the `utils` module is a better place for them.

use std::{
    convert::Infallible,
    fmt::{Debug, Display, Formatter},
    num::NonZeroUsize,
    ops::Not,
};

use generic_array::GenericArray;

mod buffers;
mod error;
mod futures;
mod gateway;
pub mod hashing;
pub(crate) mod prss_protocol;
pub mod stream;
mod transport;

use std::ops::{Index, IndexMut};

/// to validate that transport can actually send streams of this type
#[cfg(test)]
pub use buffers::OrderingSender;
pub use error::Error;
pub use futures::MaybeFuture;
use serde::{Deserialize, Serialize, Serializer};

#[cfg(feature = "stall-detection")]
mod gateway_exports {

    use crate::helpers::{
        gateway,
        gateway::{stall_detection::Observed, InstrumentedGateway},
    };

    pub type Gateway = Observed<InstrumentedGateway>;
    pub type SendingEnd<I, M> = Observed<gateway::SendingEnd<I, M>>;

    pub type MpcReceivingEnd<M> = Observed<gateway::MpcReceivingEnd<M>>;
    pub type ShardReceivingEnd<M> = Observed<gateway::ShardReceivingEnd<M>>;
}

#[cfg(not(feature = "stall-detection"))]
mod gateway_exports {
    use crate::helpers::gateway;

    pub type Gateway = gateway::Gateway;
    pub type SendingEnd<I, M> = gateway::SendingEnd<I, M>;
    pub type MpcReceivingEnd<M> = gateway::MpcReceivingEnd<M>;
    pub type ShardReceivingEnd<M> = gateway::ShardReceivingEnd<M>;
}

pub use gateway::GatewayConfig;
// TODO: this type should only be available within infra. Right now several infra modules
// are exposed at the root level. That makes it impossible to have a proper hierarchy here.
pub use gateway::{
    MpcTransportError, MpcTransportImpl, RoleResolvingTransport, ShardTransportError,
    ShardTransportImpl,
};
pub use gateway_exports::{Gateway, MpcReceivingEnd, SendingEnd, ShardReceivingEnd};
use ipa_metrics::LabelValue;
pub use prss_protocol::negotiate as negotiate_prss;
#[cfg(feature = "web-app")]
pub use transport::WrappedAxumBodyStream;
#[cfg(feature = "in-memory-infra")]
pub use transport::{
    config as in_memory_config, InMemoryMpcNetwork, InMemoryShardNetwork, InMemoryTransport,
};
pub use transport::{
    make_owned_handler, query, routing, ApiError, BodyStream, BytesStream, HandlerBox, HandlerRef,
    HelperResponse, Identity as TransportIdentity, LengthDelimitedStream, LogErrors, NoQueryId,
    NoResourceIdentifier, NoStep, QueryIdBinding, ReceiveRecords, RecordsStream, RequestHandler,
    RouteParams, ShardedTransport, SingleRecordStream, StepBinding, StreamCollection, StreamKey,
    Transport, WrappedBoxBodyStream,
};
use typenum::{Const, ToUInt, Unsigned, U8};
use x25519_dalek::PublicKey;

use crate::{
    const_assert,
    ff::Serializable,
    helpers::{
        Direction::{Left, Right},
        Role::{H1, H2, H3},
    },
    protocol::{Gate, RecordId},
    secret_sharing::Sendable,
    sharding::ShardIndex,
};

// TODO work with ArrayLength only
pub type MessagePayloadArrayLen = U8;

pub const MESSAGE_PAYLOAD_SIZE_BYTES: usize = MessagePayloadArrayLen::USIZE;

/// Represents an opaque identifier of the helper instance. Compare with a [`Role`], which
/// represents a helper's role within an MPC protocol, which may be different per protocol.
/// `HelperIdentity` will be established at startup and then never change. Components that want to
/// resolve this identifier into something (Uri, encryption keys, etc) must consult configuration
#[derive(Copy, Clone, Eq, PartialEq, Hash, PartialOrd, Ord, Deserialize)]
#[serde(try_from = "usize")]
pub struct HelperIdentity {
    id: u8,
}

// Serialize as `serde(transparent)` would. Don't see how to enable that
// for only one of (de)serialization.
impl Serialize for HelperIdentity {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.id.serialize(serializer)
    }
}

impl TryFrom<usize> for HelperIdentity {
    type Error = String;

    fn try_from(value: usize) -> std::result::Result<Self, Self::Error> {
        if value == 0 || value > 3 {
            Err(format!(
                "{value} must be within [1, 3] range to be a valid helper identity"
            ))
        } else {
            Ok(Self {
                id: u8::try_from(value).unwrap(),
            })
        }
    }
}

impl TryFrom<&str> for HelperIdentity {
    type Error = String;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        for identity in HelperIdentity::make_three() {
            if identity.as_str() == value {
                return Ok(identity);
            }
        }

        Err(format!("{value} is not a valid helper identity"))
    }
}

impl From<HelperIdentity> for u8 {
    fn from(value: HelperIdentity) -> Self {
        value.id
    }
}

impl Debug for HelperIdentity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(feature = "web-app")]
impl From<HelperIdentity> for hyper::header::HeaderValue {
    fn from(id: HelperIdentity) -> Self {
        // panic if serializing an integer fails, or is not ASCII
        hyper::header::HeaderValue::try_from(serde_json::to_string(&id).unwrap()).unwrap()
    }
}

#[cfg(test)]
impl From<i32> for HelperIdentity {
    fn from(value: i32) -> Self {
        usize::try_from(value)
            .ok()
            .and_then(|id| HelperIdentity::try_from(id).ok())
            .unwrap()
    }
}

impl Display for HelperIdentity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

impl LabelValue for HelperIdentity {
    fn hash(&self) -> u64 {
        u64::from(self.id)
    }

    fn boxed(&self) -> Box<dyn LabelValue> {
        Box::new(*self)
    }
}

impl HelperIdentity {
    pub const ONE: Self = Self { id: 1 };
    pub const TWO: Self = Self { id: 2 };
    pub const THREE: Self = Self { id: 3 };

    pub const ONE_STR: &'static str = "A";
    pub const TWO_STR: &'static str = "B";
    pub const THREE_STR: &'static str = "C";

    /// Given a helper identity, return an array of the identities of the other two helpers.
    // The order that helpers are returned here is not intended to be meaningful, however,
    // it is currently used directly to determine the assignment of roles in
    // `Processor::new_query`.
    #[must_use]
    pub fn others(&self) -> [HelperIdentity; 2] {
        match self.id {
            1 => [Self::TWO, Self::THREE],
            2 => [Self::THREE, Self::ONE],
            3 => [Self::ONE, Self::TWO],
            _ => unreachable!("helper identity out of range"),
        }
    }
}

impl HelperIdentity {
    #[must_use]
    pub fn make_three() -> [Self; 3] {
        [Self::ONE, Self::TWO, Self::THREE]
    }
}

// `HelperIdentity` is 1-indexed, so subtract 1 for `Index` values
impl<T> Index<HelperIdentity> for [T] {
    type Output = T;

    fn index(&self, index: HelperIdentity) -> &Self::Output {
        self.index(usize::from(index.id) - 1)
    }
}

// `HelperIdentity` is 1-indexed, so subtract 1 for `Index` values
impl<T> IndexMut<HelperIdentity> for [T] {
    fn index_mut(&mut self, index: HelperIdentity) -> &mut Self::Output {
        self.index_mut(usize::from(index.id) - 1)
    }
}

impl<T> Index<HelperIdentity> for Vec<T> {
    type Output = T;

    fn index(&self, index: HelperIdentity) -> &Self::Output {
        self.as_slice().index(index)
    }
}

impl<T> IndexMut<HelperIdentity> for Vec<T> {
    fn index_mut(&mut self, index: HelperIdentity) -> &mut Self::Output {
        self.as_mut_slice().index_mut(index)
    }
}

/// Represents a unique role of the helper inside the MPC circuit. Each helper may have different
/// roles in queries it processes in parallel. For some queries it can be `H1` and for others it
/// may be `H2` or `H3`.
/// Each helper instance must be able to take any role, but once the role is assigned, it cannot
/// be changed for the remainder of the query.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[serde(into = "&'static str", try_from = "&str")]
pub enum Role {
    H1 = 0,
    H2 = 1,
    H3 = 2,
}

// Some protocols execute different instructions depending on which helper they're being executed on.
// These protocols may assume certain ring directions while executed and these checks enforce the
// canonical order we provide for MPC protocols.
const_assert!(Role::eq(Role::H1.peer(Direction::Right), Role::H2));
const_assert!(Role::eq(Role::H2.peer(Direction::Left), Role::H1));
const_assert!(Role::eq(Role::H3.peer(Direction::Right), Role::H1));

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(transparent)]
pub struct RoleAssignment {
    helper_roles: [HelperIdentity; 3],
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Direction {
    Left,
    Right,
}

impl Not for Direction {
    type Output = Self;

    fn not(self) -> Self {
        match self {
            Direction::Left => Direction::Right,
            Direction::Right => Direction::Left,
        }
    }
}

impl Role {
    const H1_STR: &'static str = "H1";
    const H2_STR: &'static str = "H2";
    const H3_STR: &'static str = "H3";

    #[must_use]
    pub fn all() -> &'static [Role; 3] {
        const VARIANTS: &[Role; 3] = &[Role::H1, Role::H2, Role::H3];

        VARIANTS
    }

    /// Returns the role of a peer that is located at the specified direction
    #[must_use]
    pub const fn peer(&self, direction: Direction) -> Role {
        match (self, direction) {
            (H1, Left) | (H2, Right) => H3,
            (H1, Right) | (H3, Left) => H2,
            (H3, Right) | (H2, Left) => H1,
        }
    }

    #[must_use]
    pub fn as_static_str(&self) -> &'static str {
        match self {
            H1 => Role::H1_STR,
            H2 => Role::H2_STR,
            H3 => Role::H3_STR,
        }
    }

    /// Need `derive_const` feature to get out of nigntly to get rid of this function.
    #[must_use]
    pub const fn eq(self, other: Self) -> bool {
        matches!((self, other), (H1, H1) | (H2, H2) | (H3, H3))
    }

    /// Returns the direction to the peer with the specified role.
    ///
    /// If `self == role`, returns `None`.
    #[must_use]
    pub const fn direction_to(&self, role: Role) -> Option<Direction> {
        match (self, role) {
            (H1, H2) | (H2, H3) | (H3, H1) => Some(Direction::Right),
            (H1, H3) | (H2, H1) | (H3, H2) => Some(Direction::Left),
            (H1, H1) | (H2, H2) | (H3, H3) => None,
        }
    }
}

impl From<Role> for &'static str {
    fn from(role: Role) -> Self {
        role.as_static_str()
    }
}

impl TryFrom<&str> for Role {
    type Error = crate::error::Error;

    fn try_from(id: &str) -> std::result::Result<Self, Self::Error> {
        match id {
            Role::H1_STR => Ok(H1),
            Role::H2_STR => Ok(H2),
            Role::H3_STR => Ok(H3),
            other => Err(crate::error::Error::path_parse_error(other)),
        }
    }
}

impl AsRef<str> for Role {
    fn as_ref(&self) -> &str {
        match self {
            H1 => Role::H1_STR,
            H2 => Role::H2_STR,
            H3 => Role::H3_STR,
        }
    }
}

impl<T> Index<Role> for [T] {
    type Output = T;

    fn index(&self, index: Role) -> &Self::Output {
        let idx: usize = match index {
            Role::H1 => 0,
            Role::H2 => 1,
            Role::H3 => 2,
        };

        self.index(idx)
    }
}

impl<T> IndexMut<Role> for [T] {
    fn index_mut(&mut self, index: Role) -> &mut Self::Output {
        let idx: usize = match index {
            Role::H1 => 0,
            Role::H2 => 1,
            Role::H3 => 2,
        };

        self.index_mut(idx)
    }
}

impl<T> Index<Role> for Vec<T> {
    type Output = T;

    fn index(&self, index: Role) -> &Self::Output {
        self.as_slice().index(index)
    }
}

impl<T> IndexMut<Role> for Vec<T> {
    fn index_mut(&mut self, index: Role) -> &mut Self::Output {
        self.as_mut_slice().index_mut(index)
    }
}

impl Display for Role {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_static_str())
    }
}

impl LabelValue for Role {
    fn hash(&self) -> u64 {
        u64::from(*self as u32)
    }

    fn boxed(&self) -> Box<dyn LabelValue> {
        Box::new(*self)
    }
}

impl RoleAssignment {
    #[must_use]
    pub const fn new(helper_roles: [HelperIdentity; 3]) -> Self {
        Self { helper_roles }
    }

    /// Returns the assigned role for the given helper identity.
    ///
    /// ## Panics
    /// Panics if there is no role assigned to it.
    #[must_use]
    pub fn role(&self, id: HelperIdentity) -> Role {
        for (idx, item) in self.helper_roles.iter().enumerate() {
            if *item == id {
                return Role::all()[idx];
            }
        }

        panic!("No role assignment for {id:?} found in {self:?}")
    }

    #[must_use]
    pub fn identity(&self, role: Role) -> HelperIdentity {
        self.helper_roles[role]
    }
}

impl TryFrom<[(HelperIdentity, Role); 3]> for RoleAssignment {
    type Error = String;

    fn try_from(value: [(HelperIdentity, Role); 3]) -> std::result::Result<Self, Self::Error> {
        let mut result = [None, None, None];
        for (helper, role) in value {
            if result[role].is_some() {
                return Err(format!("Role {role:?} has been assigned twice"));
            }

            result[role] = Some(helper);
        }

        Ok(RoleAssignment::new(result.map(Option::unwrap)))
    }
}

impl TryFrom<[Role; 3]> for RoleAssignment {
    type Error = String;

    fn try_from(value: [Role; 3]) -> std::result::Result<Self, Self::Error> {
        Self::try_from([
            (HelperIdentity::ONE, value[0]),
            (HelperIdentity::TWO, value[1]),
            (HelperIdentity::THREE, value[2]),
        ])
    }
}

/// Combination of helper role and step that uniquely identifies a single channel of communication
/// between two helpers.
#[derive(Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ChannelId<I> {
    /// Entity we are talking to through this channel. It can be a source or a destination.
    pub peer: I,
    // TODO: step could be either reference or owned value. references are convenient to use inside
    // gateway , owned values can be used inside lookup tables.
    pub gate: Gate,
}

pub type HelperChannelId = ChannelId<Role>;
pub type ShardChannelId = ChannelId<ShardIndex>;

impl<I: transport::Identity> ChannelId<I> {
    #[must_use]
    pub fn new(peer: I, gate: Gate) -> Self {
        Self { peer, gate }
    }
}

impl<I: transport::Identity> Debug for ChannelId<I> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "channel[{:?},{:?}]", self.peer, self.gate.as_ref())
    }
}

/// Trait for messages that can be communicated over the network.
pub trait Message: Debug + Send + Serializable + 'static {}

/// Trait for messages that may be sent between MPC helpers. Sending raw field values may be OK,
/// sending secret shares is most definitely not OK.
///
/// This trait is not implemented for [`SecretShares`] types and there is a doctest inside [`Gateway`]
/// module that ensures compile errors are generated in this case.
///
/// [`SecretShares`]: crate::secret_sharing::replicated::ReplicatedSecretSharing
/// [`Gateway`]: crate::helpers::gateway::Gateway::get_mpc_sender
pub trait MpcMessage: Message {}

impl<V: Sendable> MpcMessage for V {}
impl<V: Debug + Send + Serializable + 'static + Sized> Message for V {}

impl Serializable for PublicKey {
    type Size = typenum::U32;
    type DeserializationError = Infallible;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        buf.copy_from_slice(self.as_bytes());
    }

    fn deserialize(
        buf: &GenericArray<u8, Self::Size>,
    ) -> std::result::Result<Self, Self::DeserializationError> {
        Ok(Self::from(<[u8; 32]>::from(*buf)))
    }
}

impl MpcMessage for PublicKey {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TotalRecords {
    Unspecified,
    Specified(NonZeroUsize),

    /// Total number of records is not well-determined. When the record ID is
    /// counting `solved_bits` attempts. The total record count for `solved_bits`
    /// depends on the number of failures.
    ///
    /// The purpose of this is to waive the warning that there is a known
    /// number of records when creating a channel.
    ///
    /// Using this is very inefficient, so avoid it.
    Indeterminate,
}

impl Display for TotalRecords {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TotalRecords::Unspecified => write!(f, "unspecified"),
            TotalRecords::Specified(v) => write!(f, "{v}"),
            TotalRecords::Indeterminate => write!(f, "∞"),
        }
    }
}

impl TotalRecords {
    pub const ONE: Self = match NonZeroUsize::new(1) {
        Some(value) => TotalRecords::Specified(value),
        None => unreachable!(),
    };

    /// ## Errors
    /// If `value` is zero. Only non-zero counts are supported.
    pub fn specified(value: usize) -> Result<Self, ZeroRecordsError> {
        match NonZeroUsize::try_from(value) {
            Ok(value) => Ok(TotalRecords::Specified(value)),
            Err(_) => Err(ZeroRecordsError),
        }
    }

    #[must_use]
    pub fn is_specified(&self) -> bool {
        !matches!(self, &TotalRecords::Unspecified)
    }

    #[must_use]
    pub fn is_indeterminate(&self) -> bool {
        matches!(self, &TotalRecords::Indeterminate)
    }

    #[must_use]
    pub fn count(&self) -> Option<usize> {
        match self {
            TotalRecords::Specified(v) => Some(v.get()),
            TotalRecords::Indeterminate | TotalRecords::Unspecified => None,
        }
    }

    /// Returns true iff the total number of records is specified and the given record is the final
    /// one to process.
    #[must_use]
    pub fn is_last<I: Into<RecordId>>(&self, record_id: I) -> bool {
        match self {
            Self::Unspecified | Self::Indeterminate => false,
            Self::Specified(v) => usize::from(record_id.into()) == v.get() - 1,
        }
    }

    /// Overwrite this value.
    /// # Panics
    /// This panics if the transition is invalid.
    /// Any new value is OK if the current value is unspecified.
    /// Otherwise the new value can be indeterminate if the old value is specified.
    #[must_use]
    pub fn overwrite<T: Into<TotalRecords>>(&self, value: T) -> TotalRecords {
        match (self, value.into()) {
            (Self::Unspecified, v) => v,
            (_, Self::Unspecified) => panic!("TotalRecords needs a specific value for overwriting"),
            (Self::Specified(_), Self::Indeterminate) => Self::Indeterminate,
            (old, new) => panic!("TotalRecords bad transition: {old:?} -> {new:?}"),
        }
    }
}

#[derive(Debug)]
pub struct ZeroRecordsError;

// This one is convenient for tests, but we don't want the panic in production code.
// For production code, use `TotalRecords::specified`.
#[cfg(test)]
impl From<usize> for TotalRecords {
    fn from(value: usize) -> Self {
        TotalRecords::specified(value).unwrap()
    }
}

impl From<NonZeroUsize> for TotalRecords {
    fn from(value: NonZeroUsize) -> Self {
        TotalRecords::Specified(value)
    }
}

impl<const N: usize> From<Const<N>> for TotalRecords
where
    Const<N>: ToUInt,
    <Const<N> as ToUInt>::Output: Unsigned + typenum::NonZero,
{
    fn from(_value: Const<N>) -> Self {
        let Some(value) = NonZeroUsize::new(<Const<N> as ToUInt>::Output::to_usize()) else {
            unreachable!("NonZero typenum cannot be zero");
        };
        TotalRecords::Specified(value)
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "TotalRecords needs a specific value for overwriting")]
    fn total_records_overwrite_unspecified() {
        let _ = TotalRecords::Specified(NonZeroUsize::new(1).unwrap())
            .overwrite(TotalRecords::Unspecified);
    }

    #[test]
    #[should_panic(expected = "ZeroRecordsError")]
    fn total_records_overwrite_zero() {
        let _ = TotalRecords::Unspecified.overwrite(0);
    }

    #[test]
    #[should_panic(expected = "TotalRecords bad transition")]
    fn total_records_overwrite_bad_transition() {
        let _ = TotalRecords::Indeterminate
            .overwrite(TotalRecords::Specified(NonZeroUsize::new(1).unwrap()));
    }

    mod role_tests {
        use super::*;

        #[test]
        pub fn peer_works() {
            assert_eq!(Role::H1.peer(Direction::Left), Role::H3);
            assert_eq!(Role::H1.peer(Direction::Right), Role::H2);
            assert_eq!(Role::H3.peer(Direction::Left), Role::H2);
            assert_eq!(Role::H3.peer(Direction::Right), Role::H1);
            assert_eq!(Role::H2.peer(Direction::Left), Role::H1);
            assert_eq!(Role::H2.peer(Direction::Right), Role::H3);
        }

        #[test]
        pub fn index_works() {
            let data = [3, 4, 5];
            assert_eq!(3, data[Role::H1]);
            assert_eq!(4, data[Role::H2]);
            assert_eq!(5, data[Role::H3]);
        }
    }

    mod helper_identity_tests {
        use ipa_metrics::LabelValue;

        use crate::helpers::HelperIdentity;

        #[test]
        fn label_value() {
            for (id, hash) in [
                (HelperIdentity::ONE, 1),
                (HelperIdentity::TWO, 2),
                (HelperIdentity::THREE, 3),
            ] {
                assert_eq!(id.boxed().hash(), hash);
            }
        }
    }

    mod role_assignment_tests {
        use crate::{
            ff::Fp31,
            helpers::{HelperIdentity, Role, RoleAssignment},
            protocol::{basics::SecureMul, context::Context, RecordId},
            rand::{thread_rng, Rng},
            test_fixture::{Reconstruct, Runner, TestWorld, TestWorldConfig},
        };

        #[test]
        fn basic() {
            let identities = HelperIdentity::make_three();
            let assignment = RoleAssignment::new(identities);

            assert_eq!(Role::H1, assignment.role(HelperIdentity::from(1)));
            assert_eq!(Role::H2, assignment.role(HelperIdentity::from(2)));
            assert_eq!(Role::H3, assignment.role(HelperIdentity::from(3)));

            assert_eq!(HelperIdentity::from(1), assignment.identity(Role::H1));
            assert_eq!(HelperIdentity::from(2), assignment.identity(Role::H2));
            assert_eq!(HelperIdentity::from(3), assignment.identity(Role::H3));
        }

        #[test]
        fn reverse() {
            let identities = (1..=3)
                .rev()
                .map(HelperIdentity::from)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            let assignment = RoleAssignment::new(identities);

            assert_eq!(Role::H3, assignment.role(HelperIdentity::from(1)));
            assert_eq!(Role::H2, assignment.role(HelperIdentity::from(2)));
            assert_eq!(Role::H1, assignment.role(HelperIdentity::from(3)));

            assert_eq!(HelperIdentity::from(3), assignment.identity(Role::H1));
            assert_eq!(HelperIdentity::from(2), assignment.identity(Role::H2));
            assert_eq!(HelperIdentity::from(1), assignment.identity(Role::H3));
        }

        #[test]
        fn illegal() {
            use Role::{H1, H2, H3};

            assert_eq!(
                RoleAssignment::try_from([H1, H1, H3]),
                Err("Role H1 has been assigned twice".into()),
            );

            assert_eq!(
                RoleAssignment::try_from([H3, H2, H3]),
                Err("Role H3 has been assigned twice".into()),
            );
        }

        #[tokio::test]
        async fn multiply_with_various_roles() {
            use Role::{H1, H2, H3};
            const ROLE_PERMUTATIONS: [[Role; 3]; 6] = [
                [H1, H2, H3],
                [H1, H3, H2],
                [H2, H1, H3],
                [H2, H3, H1],
                [H3, H1, H2],
                [H3, H2, H1],
            ];

            for &rp in &ROLE_PERMUTATIONS {
                let config = TestWorldConfig {
                    role_assignment: Some(RoleAssignment::try_from(rp).unwrap()),
                    ..TestWorldConfig::default()
                };

                let world = TestWorld::new_with(config);
                let mut rng = thread_rng();
                let a = rng.gen::<Fp31>();
                let b = rng.gen::<Fp31>();

                let res = world
                    .semi_honest((a, b), |ctx, (a, b)| async move {
                        a.multiply(&b, ctx.set_total_records(1), RecordId::from(0))
                            .await
                            .unwrap()
                    })
                    .await;

                assert_eq!(a * b, res.reconstruct());
            }
        }
    }
}

#[cfg(all(test, feature = "shuttle"))]
mod concurrency_tests {
    use futures::future::try_join;
    use rand_core::RngCore;
    use shuttle_crate::rand::thread_rng;

    use crate::{
        ff::{FieldType, Fp31, Fp32BitPrime, U128Conversions},
        helpers::{
            query::{QueryConfig, QueryType::TestMultiply},
            Direction, GatewayConfig,
        },
        protocol::{context::Context, RecordId},
        secret_sharing::replicated::{
            semi_honest, semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing,
        },
        seq_join::SeqJoin,
        test_fixture::{Reconstruct, Runner, TestApp, TestWorld, TestWorldConfig},
    };

    #[test]
    fn send_receive_sequential() {
        type TestField = Fp32BitPrime;
        shuttle::check_random(
            || {
                shuttle::future::block_on(async {
                    let input = (0u32..11).map(TestField::truncate_from).collect::<Vec<_>>();
                    let config = TestWorldConfig {
                        gateway_config: GatewayConfig {
                            active: input.len().next_power_of_two().try_into().unwrap(),
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    let world = TestWorld::new_with(config);

                    let output = world
                        .semi_honest(input.clone().into_iter(), |ctx, mut shares| async move {
                            let ctx = ctx.set_total_records(shares.len());
                            let (left_ctx, right_ctx) = (ctx.narrow("left"), ctx.narrow("right"));
                            let right_peer = ctx.role().peer(Direction::Right);
                            let left_channel = left_ctx.send_channel(right_peer);
                            let right_channel = right_ctx.send_channel(right_peer);

                            // send all shares to the right peer
                            for (i, share) in shares.iter().enumerate() {
                                let record_id = RecordId::from(i);
                                left_channel.send(record_id, share.left()).await.unwrap();
                                right_channel.send(record_id, share.right()).await.unwrap();
                            }

                            let left_peer = ctx.role().peer(Direction::Left);
                            let left_channel = left_ctx.recv_channel::<Fp32BitPrime>(left_peer);
                            let right_channel = right_ctx.recv_channel::<Fp32BitPrime>(left_peer);

                            // receive all shares from the left peer
                            for (i, share) in shares.iter_mut().enumerate() {
                                let record_id = RecordId::from(i);
                                let left = left_channel.receive(record_id).await.unwrap();
                                let right = right_channel.receive(record_id).await.unwrap();

                                *share = Replicated::new(left, right);
                            }

                            // each helper just swapped their shares, i.e. H1 now holds
                            // H3 shares, H2 holds H1 shares, etc.
                            shares
                        })
                        .await
                        .reconstruct();

                    assert_eq!(input, output);
                });
            },
            1000,
        );
    }

    #[test]
    fn send_receive_parallel() {
        type TestField = Fp32BitPrime;
        shuttle::check_random(
            || {
                shuttle::future::block_on(async {
                    let input = (0u32..11).map(TestField::truncate_from).collect::<Vec<_>>();
                    let config = TestWorldConfig {
                        gateway_config: GatewayConfig {
                            active: input.len().next_power_of_two().try_into().unwrap(),
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    let world = TestWorld::new_with(config);

                    let output = world
                        .semi_honest(input.clone().into_iter(), |ctx, shares| async move {
                            let ctx = ctx.set_total_records(shares.len());
                            let (left_ctx, right_ctx) = (ctx.narrow("left"), ctx.narrow("right"));
                            let left_peer = ctx.role().peer(Direction::Left);
                            let right_peer = ctx.role().peer(Direction::Right);

                            // send all shares to the right peer in parallel
                            let left_channel = left_ctx.send_channel(right_peer);
                            let right_channel = right_ctx.send_channel(right_peer);

                            let mut futures = Vec::with_capacity(shares.len());
                            for (i, share) in shares.iter().enumerate() {
                                let record_id = RecordId::from(i);
                                futures.push(left_channel.send(record_id, share.left()));
                                futures.push(right_channel.send(record_id, share.right()));
                            }
                            ctx.try_join(futures)
                                .await
                                .unwrap()
                                .into_iter()
                                .for_each(drop);

                            // receive all shares from the left peer in parallel
                            let left_channel = left_ctx.recv_channel::<Fp32BitPrime>(left_peer);
                            let right_channel = right_ctx.recv_channel::<Fp32BitPrime>(left_peer);
                            let mut futures = Vec::with_capacity(shares.len());
                            for i in 0..shares.len() {
                                let record_id = RecordId::from(i);
                                futures.push(try_join(
                                    left_channel.receive(record_id),
                                    right_channel.receive(record_id),
                                ));
                            }

                            let result = ctx.try_join(futures).await.unwrap();

                            result.into_iter().map(Replicated::from).collect::<Vec<_>>()
                        })
                        .await
                        .reconstruct();

                    assert_eq!(input, output);
                });
            },
            1000,
        );
    }

    #[test]
    fn execute_query() {
        shuttle::check_random(
            || {
                shuttle::future::block_on(async {
                    let app = TestApp::default();
                    let inputs = std::iter::repeat_with(|| u128::from(thread_rng().next_u64()))
                        .take(20)
                        .map(Fp31::truncate_from)
                        .collect::<Vec<_>>();
                    let sz = inputs.len();
                    assert_eq!(0, sz % 2);

                    let expected = inputs
                        .as_slice()
                        .chunks(2)
                        .map(|chunk| chunk[0] * chunk[1])
                        .collect::<Vec<_>>();

                    let results = app
                        .execute_query(
                            inputs.into_iter(),
                            QueryConfig::new(TestMultiply, FieldType::Fp31, sz).unwrap(),
                        )
                        .await
                        .unwrap();

                    let results = results.map(|bytes| {
                        semi_honest::AdditiveShare::<Fp31>::from_byte_slice_unchecked(&bytes)
                            .collect::<Vec<_>>()
                    });

                    assert_eq!(expected, results.reconstruct());
                });
            },
            1000,
        );
    }
}
