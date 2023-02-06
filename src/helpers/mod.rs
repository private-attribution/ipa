pub mod messaging;
pub mod network;
pub mod transport;

mod buffers;
mod error;
mod prss_protocol;
mod time;

pub use buffers::SendBufferConfig;
pub use error::{Error, Result};
pub use messaging::GatewayConfig;
pub use prss_protocol::negotiate as negotiate_prss;
pub use transport::{
    query, CommandEnvelope, CommandOrigin, SubscriptionType, Transport, TransportCommand,
    TransportError,
};

use crate::helpers::{
    Direction::{Left, Right},
    Role::{H1, H2, H3},
};
use std::ops::{Index, IndexMut};
use tinyvec::ArrayVec;
use typenum::{Unsigned, U8};

// TODO work with ArrayLength only
pub type MessagePayloadArrayLen = U8;
pub const MESSAGE_PAYLOAD_SIZE_BYTES: usize = MessagePayloadArrayLen::USIZE;
type MessagePayload = ArrayVec<[u8; MESSAGE_PAYLOAD_SIZE_BYTES]>;

/// Represents an opaque identifier of the helper instance. Compare with a [`Role`], which
/// represents a helper's role within an MPC protocol, which may be different per protocol.
/// `HelperIdentity` will be established at startup and then never change. Components that want to
/// resolve this identifier into something (Uri, encryption keys, etc) must consult configuration
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(
    feature = "enable-serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
pub struct HelperIdentity {
    id: u8,
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

impl From<HelperIdentity> for hyper::header::HeaderValue {
    fn from(id: HelperIdentity) -> Self {
        // does not implement `From<u8>`
        hyper::header::HeaderValue::from(u16::from(id.id))
    }
}

#[cfg(any(test, feature = "test-fixture"))]
impl HelperIdentity {
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn make_three() -> [Self; 3] {
        [
            Self::try_from(1).unwrap(),
            Self::try_from(2).unwrap(),
            Self::try_from(3).unwrap(),
        ]
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
#[derive(Copy, Clone, Debug, PartialEq, Hash, Eq)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[cfg_attr(
    feature = "enable-serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(into = "&'static str", try_from = "&str")
)]
pub enum Role {
    H1 = 0,
    H2 = 1,
    H3 = 2,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[cfg_attr(
    feature = "enable-serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
pub struct RoleAssignment {
    helper_roles: [HelperIdentity; 3],
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Direction {
    Left,
    Right,
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
    pub fn peer(&self, direction: Direction) -> Role {
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

impl RoleAssignment {
    #[must_use]
    pub fn new(helper_roles: [HelperIdentity; 3]) -> Self {
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

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;

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

    mod role_assignment_tests {
        use super::*;

        #[test]
        fn basic() {
            let identities = (1..=3)
                .map(|v| HelperIdentity::try_from(v).unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            let assignment = RoleAssignment::new(identities);

            assert_eq!(
                Role::H1,
                assignment.role(HelperIdentity::try_from(1).unwrap())
            );
            assert_eq!(
                Role::H2,
                assignment.role(HelperIdentity::try_from(2).unwrap())
            );
            assert_eq!(
                Role::H3,
                assignment.role(HelperIdentity::try_from(3).unwrap())
            );

            assert_eq!(
                HelperIdentity::try_from(1).unwrap(),
                assignment.identity(Role::H1)
            );
            assert_eq!(
                HelperIdentity::try_from(2).unwrap(),
                assignment.identity(Role::H2)
            );
            assert_eq!(
                HelperIdentity::try_from(3).unwrap(),
                assignment.identity(Role::H3)
            );
        }

        #[test]
        fn reverse() {
            let identities = (1..=3)
                .rev()
                .map(|v| HelperIdentity::try_from(v).unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            let assignment = RoleAssignment::new(identities);

            assert_eq!(
                Role::H3,
                assignment.role(HelperIdentity::try_from(1).unwrap())
            );
            assert_eq!(
                Role::H2,
                assignment.role(HelperIdentity::try_from(2).unwrap())
            );
            assert_eq!(
                Role::H1,
                assignment.role(HelperIdentity::try_from(3).unwrap())
            );

            assert_eq!(
                HelperIdentity::try_from(3).unwrap(),
                assignment.identity(Role::H1)
            );
            assert_eq!(
                HelperIdentity::try_from(2).unwrap(),
                assignment.identity(Role::H2)
            );
            assert_eq!(
                HelperIdentity::try_from(1).unwrap(),
                assignment.identity(Role::H3)
            );
        }
    }
}
