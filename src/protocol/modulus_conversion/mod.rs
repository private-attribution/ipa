mod convert_shares;

pub use convert_shares::{
    convert_all_bits, convert_all_bits_local, convert_bit, convert_bit_list, convert_bit_local,
    BitConversionTriple,
};

use crate::{ff::Field, secret_sharing::replicated::semi_honest::AdditiveShare as Replicated};

/// Split rows of bits into bits of rows such that each 2D vector can be processed as a set
///
/// input:
/// `[`
///     `[ row[0].bit0, row[0].bit1, ..., row[0].bit31 ]`,
///     `[ row[1].bit0, row[1].bit1, ..., row[1].bit31 ]`,
///     ...
///     `[ row[n].bit0, row[n].bit1, ..., row[n].bit31 ]`,
///  `]`
/// `num_multi_bits`: L
///
/// output:
///     `[ row[0].bit0, row[0].bit1, ..., row[0].bitL ], [ row[1].bit0, row[1].bit1, ..., row[1].bitL ], .. [ row[n].bit0, row[n].bit1, ..., row[n].bitL ]`,
///     `[ row[0].bitL+1, ..., row[0].bit2L ], [ row[1].bitL+1, ..., row[1].bit2L ], .. [ row[n].bitL+1, ..., row[n].bit2L ], `,
///     ...
///     `[ row[0].bitmL,  ..., row[0].bit31 ], [ row[1].bitmL, ..., row[n].bit31 ], .. [ row[n].bitmL, ..., row[n].bit31 ]`,
/// `]`
///     `[ row[0].bit0, row[0].bit1, ..., row[0].bitL ], [ row[1].bit0, row[1].bit1, ..., row[1].bitL ], .. [ row[n].bit0, row[n].bit1, ..., row[n].bitL ]`,
///     `[ row[0].bitL+1, ..., row[0].bit2L ], [ row[1].bitL+1, ..., row[1].bit2L ], .. [ row[n].bitL+1, ..., row[n].bit2L ], `,
///     ...
///     `[ row[0].bitmL,  ..., row[0].bit31 ], [ row[1].bitmL, ..., row[n].bit31 ], .. [ row[n].bitmL, ..., row[n].bit31 ]`,
/// `]`
#[must_use]
pub fn split_into_multi_bit_slices<F: Field>(
    input: &[Vec<Replicated<F>>],
    num_bits: u32,
    num_multi_bits: u32,
) -> Vec<Vec<Vec<Replicated<F>>>> {
    let total_records = input.len();
    (0..num_bits)
        .step_by(num_multi_bits as usize)
        .map(move |chunk_number| {
            (0..total_records)
                .map(|record_idx| {
                    let last_bit = std::cmp::min(chunk_number + num_multi_bits, num_bits) as usize;
                    let next_few_bits = &input[record_idx][chunk_number as usize..last_bit];
                    next_few_bits.to_vec()
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
}

/// Combine 3D vectors to get 2D vectors
///
/// input:
/// `[`
///     `[ row[0].bit0, row[0].bit1, ..., row[0].bitL ], [ row[1].bit0, row[1].bit1, ..., row[1].bitL ], .. [ row[n].bit0, row[n].bit1, ..., row[n].bitL ]`,
///     `[ row[0].bitL+1, ..., row[0].bit2L ], [ row[1].bitL+1, ..., row[1].bit2L ], .. [ row[n].bitL+1, ..., row[n].bit2L ], `,
///     ...
///     `[ row[0].bitmL,  ..., row[0].bit31 ], [ row[1].bitmL, ..., row[n].bit31 ], .. [ row[n].bitmL, ..., row[n].bit31 ]`,
/// `]`
/// `num_multi_bits`: L
///
/// output:
/// `[`
///     `[ row[0].bit0, row[0].bit1, ..., row[0].bit31 ]`,
///     `[ row[1].bit0, row[1].bit1, ..., row[1].bit31 ]`,
///     ...
///     `[ row[n].bit0, row[n].bit1, ..., row[n].bit31 ]`,
///  `]`
pub fn combine_slices<F: Field>(
    input: &[Vec<Vec<Replicated<F>>>],
    num_bits: u32,
) -> impl Iterator<Item = Vec<Replicated<F>>> + '_ {
    let record_count = input[0].len();
    let mut output = Vec::with_capacity(record_count);
    output.resize_with(record_count, || Vec::with_capacity(num_bits as usize));
    for slice in input.iter() {
        slice.iter().enumerate().for_each(|(idx, record)| {
            output[idx].append(&mut record.clone());
        });
    }
    output.into_iter()
}
