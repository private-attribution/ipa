mod convert_shares;

pub use convert_shares::{
    convert_all_bits, convert_all_bits_local, convert_bit, convert_bit_list, convert_bit_local,
    BitConversionTriple,
};

use crate::{ff::Field, secret_sharing::replicated::semi_honest::AdditiveShare as Replicated};

/// Transpose rows of bits into bits of rows
///
/// input:
/// `[`
///     `[ row[0].bit0, row[0].bit1, ..., row[0].bit31 ]`,
///     `[ row[1].bit0, row[1].bit1, ..., row[1].bit31 ]`,
///     ...
///     `[ row[n].bit0, row[n].bit1, ..., row[n].bit31 ]`,
///  `]`
///
/// output:
/// `[`
///     `[ row[0].bit0, row[1].bit0, ..., row[n].bit0 ]`,
///     `[ row[0].bit1, row[1].bit1, ..., row[n].bit1 ]`,
///     ...
///     `[ row[0].bit31, row[1].bit31, ..., row[n].bit31 ]`,
/// `]`
#[must_use]
pub fn transpose<F: Field>(input: &[Vec<Replicated<F>>]) -> Vec<Vec<Replicated<F>>> {
    (0..input[0].len())
        .map(|i| input.iter().map(|b| b[i].clone()).collect::<Vec<_>>())
        .collect::<Vec<_>>()
}
