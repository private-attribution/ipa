pub mod error;
pub mod mesh;
pub mod models;

/// Represents a unique identity of each helper running MPC computation.
#[derive(Copy, Clone, Debug, PartialEq, Hash, Eq)]
pub enum Identity {
    H1,
    H2,
    H3,
}

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
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    #[allow(clippy::missing_panics_doc)] // Panic should be impossible.
    pub fn peer(&self, direction: &Direction) -> Identity {
        let len = Identity::all_variants().len() as i32;
        let my_idx = Identity::all_variants()
            .iter()
            .position(|lhs| lhs == self)
            .unwrap() as i32;

        let peer_idx = my_idx
            + match direction {
                Direction::Left => -1,
                Direction::Right => 1,
            };
        let peer_idx = (peer_idx % len + len) % len; // peer_idx is always positive

        #[allow(clippy::cast_sign_loss)]
        Identity::all_variants()[peer_idx as usize]
    }
}

#[cfg(test)]
mod tests {
    mod identity_tests {
        use crate::helpers::{Direction, Identity};

        #[test]
        pub fn peer_works() {
            assert_eq!(Identity::H1.peer(&Direction::Left), Identity::H3);
            assert_eq!(Identity::H1.peer(&Direction::Right), Identity::H2);
            assert_eq!(Identity::H3.peer(&Direction::Left), Identity::H2);
            assert_eq!(Identity::H3.peer(&Direction::Right), Identity::H1);
            assert_eq!(Identity::H2.peer(&Direction::Left), Identity::H1);
            assert_eq!(Identity::H2.peer(&Direction::Right), Identity::H3);
        }
    }
}
