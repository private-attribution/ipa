pub mod error;
pub mod mesh;
#[cfg(test)]
pub mod mock;
pub mod prss;

/// Represents a unique identity of each helper running MPC computation.
#[derive(Copy, Clone, Debug, PartialEq, Hash, Eq)]
pub enum Identity {
    H1,
    H2,
    H3,
}

#[derive(Debug, Copy, Clone)]
pub enum Direction {
    Left,
    Right,
}

impl Identity {
    #[must_use]
    pub fn all_variants() -> &'static [Identity; 3] {
        static VARIANTS: &[Identity; 3] = &[Identity::H1, Identity::H2, Identity::H3];

        VARIANTS
    }

    /// Returns the identity of a peer that is located at the specified direction
    #[must_use]
    pub fn peer(&self, direction: Direction) -> Identity {
        use Direction::{Left, Right};
        use Identity::{H1, H2, H3};

        match (self, direction) {
            (H1, Left) | (H2, Right) => H3,
            (H1, Right) | (H3, Left) => H2,
            (H3, Right) | (H2, Left) => H1,
        }
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
    }
}
