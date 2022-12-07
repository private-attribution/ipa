use std::ops::{Index, IndexMut};
use tinyvec::ArrayVec;

mod buffers;
mod error;
pub mod messaging;
pub mod network;

use crate::helpers::Direction::{Left, Right};
use crate::helpers::Role::{H1, H2, H3};
pub use buffers::SendBufferConfig;
pub use error::Error;
pub use error::Result;
pub use messaging::GatewayConfig;

pub const MESSAGE_PAYLOAD_SIZE_BYTES: usize = 8;
type MessagePayload = ArrayVec<[u8; MESSAGE_PAYLOAD_SIZE_BYTES]>;

/// Represents a unique role of the helper inside the MPC circuit. Each helper may have different
/// roles in queries it processes in parallel. For some queries it can be `H1` and for others it
/// may be `H2` or `H3`.
/// Each helper instance must be able to take any role, but once the role is assigned, it cannot
/// be changed for the remainder of the query.
#[derive(Copy, Clone, Debug, PartialEq, Hash, Eq)]
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

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Direction {
    Left,
    Right,
}

impl Role {
    const H1_STR: &'static str = "h1";
    const H2_STR: &'static str = "h2";
    const H3_STR: &'static str = "h3";

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
}
