pub mod apply_sort;
pub mod bit_permutation;
pub mod generate_permutation;
pub mod generate_permutation_opt;

mod apply;
mod compose;
mod multi_bit_permutation;
mod secureapplyinv;
mod shuffle;

use crate::{
    error::Error,
    ff::Field,
    protocol::{
        context::Context,
        step::{BitOpStep, Step},
        BasicProtocols, RecordId,
    },
    repeat64str,
    secret_sharing::{BitDecomposed, Linear as LinearSecretSharing, SecretSharing},
};
use ipa_macros::step;
use std::fmt::Debug;
use strum::AsRefStr;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub(crate) enum SortStep {
    BitPermutationStep,
    ComposeStep,
    ShuffleRevealPermutation,
    SortKeys,
    MultiApplyInv(u32),
}

impl Step for SortStep {}

impl AsRef<str> for SortStep {
    fn as_ref(&self) -> &str {
        const MULTI_APPLY_INV: [&str; 64] = repeat64str!["multi_apply_inv"];
        match self {
            Self::BitPermutationStep => "bit_permute",
            Self::ComposeStep => "compose",
            Self::ShuffleRevealPermutation => "shuffle_reveal_permutation",
            Self::SortKeys => "sort_keys",
            Self::MultiApplyInv(i) => MULTI_APPLY_INV[usize::try_from(*i).unwrap()],
        }
    }
}

#[step]
pub(crate) enum ShuffleStep {
    Shuffle1,
    Shuffle2,
    Shuffle3,
}

#[step]
pub(crate) enum ApplyInvStep {
    ShuffleInputs,
}

#[step]
pub(crate) enum ComposeStep {
    UnshuffleRho,
}

#[step]
pub(crate) enum ShuffleRevealPermutationStep {
    Generate,
    Reveal,
    Shuffle,
}

#[step]
pub(crate) enum ReshareStep {
    RandomnessForValidation,
    ReshareRx,
}

///
/// This function accepts a sequence of N secret-shared bits.
/// When considered as a bitwise representation of an N-bit unsigned number, it's clear that there are exactly
/// `2^N` possible values this could have.
/// This function checks all of these possible values, and returns a vector of secret-shared results.
/// Only one result will be a secret-sharing of one, all of the others will be secret-sharings of zero.
///
/// # Errors
/// If any multiplication fails, or if the record is too long (e.g. more than 64 multiplications required)
pub async fn check_everything<F, C, S>(
    ctx: C,
    record_idx: usize,
    record: &[S],
) -> Result<BitDecomposed<S>, Error>
where
    F: Field,
    C: Context,
    S: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    let num_bits = record.len();
    let precomputed_combinations =
        pregenerate_all_combinations(ctx, record_idx, record, num_bits).await?;

    // This loop just iterates over all the possible values this N-bit input could potentially represent
    // and checks if the bits are equal to this value. It does so by computing a linear combination of the
    // pre-computed coefficients.
    //
    // Observe that whether a given precomputed coefficient contributes to a
    // given equality check follows a Sierpiński triangle
    // https://en.wikipedia.org/wiki/Sierpi%C5%84ski_triangle#/media/File:Multigrade_operator_AND.svg.
    //
    // For example, for a three bit value, we have the following:
    // 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1
    // 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1
    // 0 | 0 | 1 | 1 | 0 | 0 | 1 | 1
    // 0 | 0 | 0 | 1 | 0 | 0 | 0 | 1
    // 0 | 0 | 0 | 0 | 1 | 1 | 1 | 1
    // 0 | 0 | 0 | 0 | 0 | 1 | 0 | 1
    // 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1
    // 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1
    //
    // This can be computed from row (i) and column (j) indices with i & j == i
    //
    // The sign of the inclusion is less obvious, but we discovered that this
    // can be found by taking the same row (i) and column (j) indices:
    // 1. Invert the row index and bitwise AND the values: a = !i & j
    // 2. Count the number of bits that are set: b = a.count_ones()
    // 3. An odd number means a positive coefficient; an odd number means a negative.
    //
    // For example, for a three bit value, step 1 produces (in binary):
    // 000 | 001 | 010 | 011 | 100 | 101 | 110 | 111
    // 000 | 000 | 010 | 010 | 100 | 100 | 110 | 110
    // 000 | 001 | 000 | 001 | 100 | 101 | 100 | 101
    // 000 | 000 | 000 | 000 | 100 | 100 | 100 | 100
    // 000 | 001 | 010 | 011 | 000 | 001 | 010 | 011
    // 000 | 000 | 010 | 010 | 000 | 000 | 010 | 010
    // 000 | 001 | 000 | 001 | 000 | 001 | 000 | 001
    // 000 | 000 | 000 | 000 | 000 | 000 | 000 | 000
    //
    // Where 000, 101, 011, and 110 mean positive contributions, and
    // 001, 010, 100, and 111 mean negative contributions.
    let side_length = 1 << num_bits;
    Ok(BitDecomposed::decompose(side_length, |i| {
        let mut check = S::ZERO;
        for (j, combination) in precomputed_combinations.iter().enumerate() {
            let bit: i8 = i8::from((i & j) == i);
            if bit > 0 {
                if (!i & j).count_ones() & 1 == 1 {
                    check -= combination;
                } else {
                    check += combination;
                }
            }
        }
        check
    }))
}

//
// Every equality check can be computed as a linear combination of coefficients.
// For example, if we are given a 3-bit number `[x_3, x_2, x_1]`,
// we can check if it is equal to 4, by computing:
// $x_3(1-x_2)(1-x_1)$,
// which expands to:
// $x_3 - x_2*x_3 - x_1*x_3 + x_1*x_2*x_3$
//
// Since we need to check all possible values, it makes sense to pre-compute all
// of the coefficients that are used across all of these equality checks. In this way,
// we can minimize the total number of multiplications needed.
//
// We must pre-compute all combinations of bit values. The following loop does so.
// It does so by starting with the array `[1]`.
// The next step is to multiply this by `x_1` and append it to the end of the array.
// Now the array is `[1, x_1]`.
// The next step is to mulitply all of these values by `x_2` and append them to the end of the array.
// Now the array is `[1, x_1, x_2, x_1*x_2]`
// The next step is to mulitply all of these values of `x_3` and append them to the end of the array.
// Now the array is `[1, x_1, x_2, x_1*x_2, x_3, x_1*x_3, x_2*x_3, x_1*x_2*x_3]`
// This process continues for as many steps as there are bits of input.
async fn pregenerate_all_combinations<F, C, S>(
    ctx: C,
    record_idx: usize,
    input: &[S],
    num_bits: usize,
) -> Result<Vec<S>, Error>
where
    F: Field,
    C: Context,
    S: SecretSharing<F> + BasicProtocols<C, F>,
{
    let record_id = RecordId::from(record_idx);
    let mut precomputed_combinations = Vec::with_capacity(1 << num_bits);
    precomputed_combinations.push(S::share_known_value(&ctx, F::ONE));
    for (bit_idx, bit) in input.iter().enumerate() {
        let step = 1 << bit_idx;
        // Concurrency needed here because we are operating on different bits for the same record.
        let mut multiplication_results = ctx
            .parallel_join(precomputed_combinations.iter().skip(1).enumerate().map(
                |(j, precomputed_combination)| {
                    let child_idx = j + step;
                    precomputed_combination.multiply(
                        bit,
                        ctx.narrow(&BitOpStep::from(child_idx)),
                        record_id,
                    )
                },
            ))
            .await?;
        precomputed_combinations.push(bit.clone());
        precomputed_combinations.append(&mut multiplication_results);
    }
    Ok(precomputed_combinations)
}
