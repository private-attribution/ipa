pub mod messaging;
pub mod network;
pub mod old_http;
pub mod old_network;

mod buffers;
mod error;
mod transport;

pub use buffers::SendBufferConfig;
pub use error::{Error, Result};
pub use messaging::GatewayConfig;
pub use transport::{Transport, SubscriptionType, TransportCommand, TransportError, NetworkEventData};

use crate::helpers::{
    Direction::{Left, Right},
    Role::{H1, H2, H3},
};
use std::ops::{Index, IndexMut};
use tinyvec::ArrayVec;

pub const MESSAGE_PAYLOAD_SIZE_BYTES: usize = 8;
type MessagePayload = ArrayVec<[u8; MESSAGE_PAYLOAD_SIZE_BYTES]>;

/// Represents a unique identifier of the helper instance. Compare with a [`Role`], which
/// represents a helper's role within an MPC protocol, which may be different per protocol.
/// `HelperIdentity` will be established at startup and then never change.
/// TODO: must be cheap (i.e. copy) and probably just a byte. Whoever needs to resolve it to Uri
/// would use this token to pull helper configuration
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(
    feature = "enable-serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
pub struct HelperIdentity {
    #[cfg(not(test))]
    #[cfg_attr(feature = "enable-serde", serde(with = "crate::uri"))]
    uri: hyper::Uri,

    #[cfg(test)]
    id: u8
}

#[cfg(test)]
impl From<usize> for HelperIdentity {
    fn from(value: usize) -> Self {
        assert!(value < 3);

        Self {
            id: u8::try_from(value).unwrap()
        }
    }
}

#[cfg(not(test))]
impl From<hyper::Uri> for HelperIdentity {
    fn from(uri: hyper::Uri) -> Self {
        Self { uri }
    }
}

/// Represents a unique role of the helper inside the MPC circuit. Each helper may have different
/// roles in queries it processes in parallel. For some queries it can be `H1` and for others it
/// may be `H2` or `H3`.
/// Each helper instance must be able to take any role, but once the role is assigned, it cannot
/// be changed for the remainder of the query.
#[derive(Copy, Clone, Debug, PartialEq, Hash, Eq, clap::ValueEnum)]
#[cfg_attr(
    feature = "enable-serde",
    derive(serde::Deserialize),
    serde(try_from = "&str")
)]
pub enum Role {
    H1 = 0,
    H2 = 1,
    H3 = 2,
}

#[derive(Debug)]
#[cfg_attr(any(test, feature = "test-fixture"), derive(Clone))]
pub struct RoleAssignment {
    helper_roles: [HelperIdentity; 3]
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
    pub fn new(helper_roles: [HelperIdentity; 3]) -> Self {
        Self {
            helper_roles
        }
    }

    pub fn role(&self, id: &HelperIdentity) -> Role {
        for (idx, item) in self.helper_roles.iter().enumerate() {
            if item == id {
                return Role::all()[idx]
            }
        }

        panic!("No role assignment for {id:?} found in {self:?}")
    }

    pub fn identity(&self, role: Role) -> &HelperIdentity {
        &self.helper_roles[role]
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    mod role_tests {
        use crate::helpers::{Direction, Role};

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
        use crate::helpers::*;

        #[test]
        fn basic() {
            let identities = (0..3).map(HelperIdentity::from)
                .collect::<Vec<_>>()
                .try_into().unwrap();
            let assignment = RoleAssignment::new(identities);

            assert_eq!(Role::H1, assignment.role(&HelperIdentity::from(0)));
            assert_eq!(Role::H2, assignment.role(&HelperIdentity::from(1)));
            assert_eq!(Role::H3, assignment.role(&HelperIdentity::from(2)));

            assert_eq!(&HelperIdentity::from(0), assignment.identity(Role::H1));
            assert_eq!(&HelperIdentity::from(1), assignment.identity(Role::H2));
            assert_eq!(&HelperIdentity::from(2), assignment.identity(Role::H3));
        }

        #[test]
        fn reverse() {
            let identities = (0..3).rev().map(HelperIdentity::from)
                .collect::<Vec<_>>()
                .try_into().unwrap();
            let assignment = RoleAssignment::new(identities);

            assert_eq!(Role::H3, assignment.role(&HelperIdentity::from(0)));
            assert_eq!(Role::H2, assignment.role(&HelperIdentity::from(1)));
            assert_eq!(Role::H1, assignment.role(&HelperIdentity::from(2)));

            assert_eq!(&HelperIdentity::from(2), assignment.identity(Role::H1));
            assert_eq!(&HelperIdentity::from(1), assignment.identity(Role::H2));
            assert_eq!(&HelperIdentity::from(0), assignment.identity(Role::H3));
        }
    }
}
