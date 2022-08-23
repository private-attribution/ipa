pub mod error;
pub mod models;
pub mod ring;

/// Represents a unique identity of each helper running MPC computation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Identity {
    H1,
    H2,
    H3,
}
