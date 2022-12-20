// ff - Finite Fields
//
// This is where we store arithmetic shared secret data models.

mod field;
mod prime_field;

pub use field::{BinaryField, Field, Int};
pub use prime_field::{Fp2, Fp31, Fp32BitPrime};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FieldType {
    Fp31,
    Fp32BitPrime,
}
