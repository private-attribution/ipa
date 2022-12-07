// ff - Finite Fields
//
// This is where we store arithmetic shared secret data models.

mod field;
mod prime_field;

pub use field::{size_in_bytes_from_type_str, BinaryField, Field, Int};
pub use prime_field::{Fp2, Fp31, Fp32BitPrime};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unknown field type {type_str}")]
    UnknownField { type_str: String },
}
