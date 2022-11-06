use std::ops::{Index, IndexMut};

mod buffers;
mod error;
pub mod fabric;
pub mod messaging;

use crate::helpers::Direction::{Left, Right};
use crate::helpers::Identity::{H1, H2, H3};
pub use error::Error;
pub use error::Result;

/// Represents a unique identity of each helper running MPC computation.
#[derive(Copy, Clone, Debug, PartialEq, Hash, Eq)]
#[cfg_attr(
    feature = "enable-serde",
    derive(serde::Deserialize),
    serde(try_from = "&str")
)]
pub enum Identity {
    H1,
    H2,
    H3,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Direction {
    Left,
    Right,
}

impl Identity {
    const H1_STR: &'static str = "h1";
    const H2_STR: &'static str = "h2";
    const H3_STR: &'static str = "h3";

    #[must_use]
    pub fn all_variants() -> &'static [Identity; 3] {
        static VARIANTS: &[Identity; 3] = &[Identity::H1, Identity::H2, Identity::H3];

        VARIANTS
    }

    /// Returns the identity of a peer that is located at the specified direction
    #[must_use]
    pub fn peer(&self, direction: Direction) -> Identity {
        match (self, direction) {
            (H1, Left) | (H2, Right) => H3,
            (H1, Right) | (H3, Left) => H2,
            (H3, Right) | (H2, Left) => H1,
        }
    }
}

impl TryFrom<&str> for Identity {
    type Error = crate::error::Error;

    fn try_from(id: &str) -> std::result::Result<Self, Self::Error> {
        match id {
            Identity::H1_STR => Ok(H1),
            Identity::H2_STR => Ok(H2),
            Identity::H3_STR => Ok(H3),
            other => Err(crate::error::Error::path_parse_error(other)),
        }
    }
}

impl AsRef<str> for Identity {
    fn as_ref(&self) -> &str {
        match self {
            H1 => Identity::H1_STR,
            H2 => Identity::H2_STR,
            H3 => Identity::H3_STR,
        }
    }
}

impl<T> Index<Identity> for [T] {
    type Output = T;

    fn index(&self, index: Identity) -> &Self::Output {
        let idx: usize = match index {
            Identity::H1 => 0,
            Identity::H2 => 1,
            Identity::H3 => 2,
        };

        self.index(idx)
    }
}

impl<T> IndexMut<Identity> for [T] {
    fn index_mut(&mut self, index: Identity) -> &mut Self::Output {
        let idx: usize = match index {
            Identity::H1 => 0,
            Identity::H2 => 1,
            Identity::H3 => 2,
        };

        self.index_mut(idx)
    }
}

impl<T> Index<Identity> for Vec<T> {
    type Output = T;

    fn index(&self, index: Identity) -> &Self::Output {
        self.as_slice().index(index)
    }
}

impl<T> IndexMut<Identity> for Vec<T> {
    fn index_mut(&mut self, index: Identity) -> &mut Self::Output {
        self.as_mut_slice().index_mut(index)
    }
}

#[cfg(test)]
mod tests {
    mod identity_tests {
        use crate::helpers::{Direction, Identity};

        #[test]
        pub fn peer_works() {
            assert_eq!(Identity::H1.peer(Direction::Left), Identity::H3);
            assert_eq!(Identity::H1.peer(Direction::Right), Identity::H2);
            assert_eq!(Identity::H3.peer(Direction::Left), Identity::H2);
            assert_eq!(Identity::H3.peer(Direction::Right), Identity::H1);
            assert_eq!(Identity::H2.peer(Direction::Left), Identity::H1);
            assert_eq!(Identity::H2.peer(Direction::Right), Identity::H3);
        }

        #[test]
        pub fn index_works() {
            let data = [3, 4, 5];
            assert_eq!(3, data[Identity::H1]);
            assert_eq!(4, data[Identity::H2]);
            assert_eq!(5, data[Identity::H3]);
        }
    }
}
