// ff - Finite Fields
//
// This is where we store arithmetic shared secret data models.

mod field;
mod prime_field;

pub use field::{BinaryField, Field, FieldTypeStr, Int};
pub use prime_field::{Fp2, Fp31, Fp32BitPrime};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unknown field type {type_str}")]
    UnknownField { type_str: String },
}
