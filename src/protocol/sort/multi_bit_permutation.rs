use std::iter::repeat;

use crate::{
    error::Error,
    ff::Field,
    protocol::{context::Context, sort::bit_permutation::bit_permutation, BitOpStep, RecordId},
    secret_sharing::SecretSharing,
};

use futures::future::try_join_all;

// indicies reference elements in this array:
// [
//   1,
//   x_1,
// ]
const COEFFICIENT_LOOK_UP_TABLE_ONE_BIT: &[&[i8]] = &[
    // 1 - x_1
    &[0, -1],
    // x_1
    &[1],
];

// indicies reference elements in this array:
// [
//   1,
//   x_1,
//   x_2, x_1*x_2,
// ]
const COEFFICIENT_LOOK_UP_TABLE_TWO_BITS: &[&[i8]] = &[
    // 1 - x_2 - x_1 + x_1*x_2
    &[0, -2, -1, 3],
    // x_1 - x_1*x_2
    &[1, -3],
    // x_2 - x_1*x_2
    &[2, -3],
    // x_1*x_2
    &[3],
];

// indicies reference elements in this array:
// [
//   1,
//   x_1,
//   x_2, x_1*x_2,
//   x_3, x_1*x_3, x_2*x_3, x_1*x_2*x_3,
// ]
const COEFFICIENT_LOOK_UP_TABLE_THREE_BITS: &[&[i8]] = &[
    // 1 - x_3 - x_2 + x_2*x_3 - x_1 + x_1*x_3 + x_1*x_2 - x_1*x_2*x_3
    &[0, -4, -2, 6, -1, 5, 3, -7],
    // x_1 - x_1*x_3 - x_1*x_2 + x_1*x_2*x_3
    &[1, -5, -3, 7],
    // x_2 - x_2*x_3 - x_1*x_2 + x_1*x_2*x_3
    &[2, -6, -3, 7],
    // x_1*x_2 - x_1*x_2*x_3
    &[3, -7],
    // x_3 - x_2*x_3 - x_1*x_3 + x_1*x_2*x_3
    &[4, -6, -5, 7],
    // x_1*x_3 - x_1*x_2*x_3
    &[5, -7],
    // x_2*x_3 - x_1*x_2*x_3
    &[6, -7],
    // x_1*x_2*x_3
    &[7],
];

// indicies reference elements in this array:
// [
//   1,
//   x_1,
//   x_2, x_1*x_2,
//   x_3, x_1*x_3, x_2*x_3, x_1*x_2*x_3,
//   x_4, x_1*x_4, x_2*x_4, x_1*x_2*x_4, x_3*x_4, x_1*x_3*x_4, x_2*x_3*x_4, x_1*x_2*x_3*x_4
// ]
const COEFFICIENT_LOOK_UP_TABLE_FOUR_BITS: &[&[i8]] = &[
    // 1 - x_4 - x_3 + x_3*x_4 - x_2 + x_2*x_4 + x_2*x_3 - x_2*x_3*x_4 - x_1 + x_1*x_4 + x_1*x_3 - x_1*x_3*x_4 + x_1*x_2 - x_1*x_2*x_4 - x_1*x_2*x_3 + x_1*x_2*x_3*x_4
    &[0, -8, -4, 12, -2, 10, 6, -14, -1, 9, 5, -13, 3, -11, -7, 15],
    // x_1 - x_1*x_4 - x_1*x_3 + x_1*x_3*x_4 - x_1*x_2 + x_1*x_2*x_4 + x_1*x_2*x_3 - x_1*x_2*x_3*x_4
    &[1, -9, -5, 13, -3, 11, 7, -15],
    // x_2 - x_2*x_4 - x_2*x_3 + x_2*x_3*x_4 - x_1*x_2 + x_1*x_2*x_4 + x_1*x_2*x_3 - x_1*x_2*x_3*x_4
    &[2, -10, -6, 14, -3, 11, 7, -15],
    // x_1*x_2 - x_1*x_2*x_4 - x_1*x_2*x_3 + x_1*x_2*x_3*x_4
    &[3, -11, -7, 15],
    // x_3 - x_3*x_4 - x_2*x_3 + x_2*x_3*x_4 - x_1*x_3 + x_1*x_3*x_4 + x_1*x_2*x_3 - x_1*x_2*x_3*x_4
    &[4, -12, -6, 14, -5, 13, 7, -15],
    // x_1*x_3 - x_1*x_3*x_4 - x_1*x_2*x_3 + x_1*x_2*x_3*x_4
    &[5, -13, -7, 15],
    // x_2*x_3 - x_2*x_3*x_4 - x_1*x_2*x_3 + x_1*x_2*x_3*x_4
    &[6, -14, -7, 15],
    // x_1*x_2*x_3 - x_1*x_2*x_3*x_4
    &[7, -15],
    // x_4 - x_3*x_4 - x_2*x_4 + x_2*x_3*x_4 - x_1*x_4 + x_1*x_3*x_4 + x_1*x_2*x_4 - x_1*x_2*x_3*x_4
    &[8, -12, -10, 14, -9, 13, 11, -15],
    // x_1*x_4 - x_1*x_3*x_4 - x_1*x_2*x_4 + x_1*x_2*x_3*x_4
    &[9, -13, -11, 15],
    // x_2*x_4 - x_2*x_3*x_4 - x_1*x_2*x_4 + x_1*x_2*x_3*x_4
    &[10, -14, -11, 15],
    // x_1*x_2*x_4 - x_1*x_2*x_3*x_4
    &[11, -15],
    // x_3*x_4 - x_2*x_3*x_4 - x_1*x_3*x_4 + x_1*x_2*x_3*x_4
    &[12, -14, -13, 15],
    // x_1*x_3*x_4 - x_1*x_2*x_3*x_4
    &[13, -15],
    // x_2*x_3*x_4 - x_1*x_2*x_3*x_4
    &[14, -15],
    // x_1*x_2*x_3*x_4
    &[15],
];

// indicies reference elements in this array:
// [
//   1,
//   x_1,
//   x_2, x_1*x_2,
//   x_3, x_1*x_3, x_2*x_3, x_1*x_2*x_3,
//   x_4, x_1*x_4, x_2*x_4, x_1*x_2*x_4, x_3*x_4, x_1*x_3*x_4, x_2*x_3*x_4, x_1*x_2*x_3*x_4
//   x_5, x_1*x_5, x_2*x_5, x_1*x_2*x_5, x_3*x_5, x_1*x_3*x_5, x_2*x_3*x_5, x_1*x_2*x_3*x_5, x_4*x_5, x_1*x_4*x_5, x_2*x_4*x_5, x_1*x_2*x_4*x_5, x_3*x_4*x_5, x_1*x_3*x_4*x_5, x_2*x_3*x_4*x_5, x_1*x_2*x_3*x_4*x_5
// ]
const COEFFICIENT_LOOK_UP_TABLE_FIVE_BITS: &[&[i8]] = &[
    // 1 - x_5 - x_4 + x_4*x_5 - x_3 + x_3*x_5 + x_3*x_4 - x_3*x_4*x_5 - x_2 + x_2*x_5 + x_2*x_4 - x_2*x_4*x_5 + x_2*x_3 - x_2*x_3*x_5 - x_2*x_3*x_4 + x_2*x_3*x_4*x_5 - x_1 + x_1*x_5 + x_1*x_4 - x_1*x_4*x_5 + x_1*x_3 - x_1*x_3*x_5 - x_1*x_3*x_4 + x_1*x_3*x_4*x_5 + x_1*x_2 - x_1*x_2*x_5 - x_1*x_2*x_4 + x_1*x_2*x_4*x_5 - x_1*x_2*x_3 + x_1*x_2*x_3*x_5 + x_1*x_2*x_3*x_4 - x_1*x_2*x_3*x_4*x_5
    &[
        0, -16, -8, 24, -4, 20, 12, -28, -2, 18, 10, -26, 6, -22, -14, 30, -1, 17, 9, -25, 5, -21,
        -13, 29, 3, -19, -11, 27, -7, 23, 15, -31,
    ],
    // x_1 - x_1*x_5 - x_1*x_4 + x_1*x_4*x_5 - x_1*x_3 + x_1*x_3*x_5 + x_1*x_3*x_4 - x_1*x_3*x_4*x_5 - x_1*x_2 + x_1*x_2*x_5 + x_1*x_2*x_4 - x_1*x_2*x_4*x_5 + x_1*x_2*x_3 - x_1*x_2*x_3*x_5 - x_1*x_2*x_3*x_4 + x_1*x_2*x_3*x_4*x_5
    &[
        1, -17, -9, 25, -5, 21, 13, -29, -3, 19, 11, -27, 7, -23, -15, 31,
    ],
    // x_2 - x_2*x_5 - x_2*x_4 + x_2*x_4*x_5 - x_2*x_3 + x_2*x_3*x_5 + x_2*x_3*x_4 - x_2*x_3*x_4*x_5 - x_1*x_2 + x_1*x_2*x_5 + x_1*x_2*x_4 - x_1*x_2*x_4*x_5 + x_1*x_2*x_3 - x_1*x_2*x_3*x_5 - x_1*x_2*x_3*x_4 + x_1*x_2*x_3*x_4*x_5
    &[
        2, -18, -10, 26, -6, 22, 14, -30, -3, 19, 11, -27, 7, -23, -15, 31,
    ],
    // x_1*x_2 - x_1*x_2*x_5 - x_1*x_2*x_4 + x_1*x_2*x_4*x_5 - x_1*x_2*x_3 + x_1*x_2*x_3*x_5 + x_1*x_2*x_3*x_4 - x_1*x_2*x_3*x_4*x_5
    &[3, -19, -11, 27, -7, 23, 15, -31],
    // x_3 - x_3*x_5 - x_3*x_4 + x_3*x_4*x_5 - x_2*x_3 + x_2*x_3*x_5 + x_2*x_3*x_4 - x_2*x_3*x_4*x_5 - x_1*x_3 + x_1*x_3*x_5 + x_1*x_3*x_4 - x_1*x_3*x_4*x_5 + x_1*x_2*x_3 - x_1*x_2*x_3*x_5 - x_1*x_2*x_3*x_4 + x_1*x_2*x_3*x_4*x_5
    &[
        4, -20, -12, 28, -6, 22, 14, -30, -5, 21, 13, -29, 7, -23, -15, 31,
    ],
    // x_1*x_3 - x_1*x_3*x_5 - x_1*x_3*x_4 + x_1*x_3*x_4*x_5 - x_1*x_2*x_3 + x_1*x_2*x_3*x_5 + x_1*x_2*x_3*x_4 - x_1*x_2*x_3*x_4*x_5
    &[5, -21, -13, 29, -7, 23, 15, -31],
    // x_2*x_3 - x_2*x_3*x_5 - x_2*x_3*x_4 + x_2*x_3*x_4*x_5 - x_1*x_2*x_3 + x_1*x_2*x_3*x_5 + x_1*x_2*x_3*x_4 - x_1*x_2*x_3*x_4*x_5
    &[6, -22, -14, 30, -7, 23, 15, -31],
    // x_1*x_2*x_3 - x_1*x_2*x_3*x_5 - x_1*x_2*x_3*x_4 + x_1*x_2*x_3*x_4*x_5
    &[7, -23, -15, 31],
    // x_4 - x_4*x_5 - x_3*x_4 + x_3*x_4*x_5 - x_2*x_4 + x_2*x_4*x_5 + x_2*x_3*x_4 - x_2*x_3*x_4*x_5 - x_1*x_4 + x_1*x_4*x_5 + x_1*x_3*x_4 - x_1*x_3*x_4*x_5 + x_1*x_2*x_4 - x_1*x_2*x_4*x_5 - x_1*x_2*x_3*x_4 + x_1*x_2*x_3*x_4*x_5
    &[
        8, -24, -12, 28, -10, 26, 14, -30, -9, 25, 13, -29, 11, -27, -15, 31,
    ],
    // x_1*x_4 - x_1*x_4*x_5 - x_1*x_3*x_4 + x_1*x_3*x_4*x_5 - x_1*x_2*x_4 + x_1*x_2*x_4*x_5 + x_1*x_2*x_3*x_4 - x_1*x_2*x_3*x_4*x_5
    &[9, -25, -13, 29, -11, 27, 15, -31],
    // x_2*x_4 - x_2*x_4*x_5 - x_2*x_3*x_4 + x_2*x_3*x_4*x_5 - x_1*x_2*x_4 + x_1*x_2*x_4*x_5 + x_1*x_2*x_3*x_4 - x_1*x_2*x_3*x_4*x_5
    &[10, -26, -14, 30, -11, 27, 15, -31],
    // x_1*x_2*x_4 - x_1*x_2*x_4*x_5 - x_1*x_2*x_3*x_4 + x_1*x_2*x_3*x_4*x_5
    &[11, -27, -15, 31],
    // x_3*x_4 - x_3*x_4*x_5 - x_2*x_3*x_4 + x_2*x_3*x_4*x_5 - x_1*x_3*x_4 + x_1*x_3*x_4*x_5 + x_1*x_2*x_3*x_4 - x_1*x_2*x_3*x_4*x_5
    &[12, -28, -14, 30, -13, 29, 15, -31],
    // x_1*x_3*x_4 - x_1*x_3*x_4*x_5 - x_1*x_2*x_3*x_4 + x_1*x_2*x_3*x_4*x_5
    &[13, -29, -15, 31],
    // x_2*x_3*x_4 - x_2*x_3*x_4*x_5 - x_1*x_2*x_3*x_4 + x_1*x_2*x_3*x_4*x_5
    &[14, -30, -15, 31],
    // x_1*x_2*x_3*x_4 - x_1*x_2*x_3*x_4*x_5
    &[15, -31],
    // x_5 - x_4*x_5 - x_3*x_5 + x_3*x_4*x_5 - x_2*x_5 + x_2*x_4*x_5 + x_2*x_3*x_5 - x_2*x_3*x_4*x_5 - x_1*x_5 + x_1*x_4*x_5 + x_1*x_3*x_5 - x_1*x_3*x_4*x_5 + x_1*x_2*x_5 - x_1*x_2*x_4*x_5 - x_1*x_2*x_3*x_5 + x_1*x_2*x_3*x_4*x_5
    &[
        16, -24, -20, 28, -18, 26, 22, -30, -17, 25, 21, -29, 19, -27, -23, 31,
    ],
    // x_1*x_5 - x_1*x_4*x_5 - x_1*x_3*x_5 + x_1*x_3*x_4*x_5 - x_1*x_2*x_5 + x_1*x_2*x_4*x_5 + x_1*x_2*x_3*x_5 - x_1*x_2*x_3*x_4*x_5
    &[17, -25, -21, 29, -19, 27, 23, -31],
    // x_2*x_5 - x_2*x_4*x_5 - x_2*x_3*x_5 + x_2*x_3*x_4*x_5 - x_1*x_2*x_5 + x_1*x_2*x_4*x_5 + x_1*x_2*x_3*x_5 - x_1*x_2*x_3*x_4*x_5
    &[18, -26, -22, 30, -19, 27, 23, -31],
    // x_1*x_2*x_5 - x_1*x_2*x_4*x_5 - x_1*x_2*x_3*x_5 + x_1*x_2*x_3*x_4*x_5
    &[19, -27, -23, 31],
    // x_3*x_5 - x_3*x_4*x_5 - x_2*x_3*x_5 + x_2*x_3*x_4*x_5 - x_1*x_3*x_5 + x_1*x_3*x_4*x_5 + x_1*x_2*x_3*x_5 - x_1*x_2*x_3*x_4*x_5
    &[20, -28, -22, 30, -21, 29, 23, -31],
    // x_1*x_3*x_5 - x_1*x_3*x_4*x_5 - x_1*x_2*x_3*x_5 + x_1*x_2*x_3*x_4*x_5
    &[21, -29, -23, 31],
    // x_2*x_3*x_5 - x_2*x_3*x_4*x_5 - x_1*x_2*x_3*x_5 + x_1*x_2*x_3*x_4*x_5
    &[22, -30, -23, 31],
    // x_1*x_2*x_3*x_5 - x_1*x_2*x_3*x_4*x_5
    &[23, -31],
    // x_4*x_5 - x_3*x_4*x_5 - x_2*x_4*x_5 + x_2*x_3*x_4*x_5 - x_1*x_4*x_5 + x_1*x_3*x_4*x_5 + x_1*x_2*x_4*x_5 - x_1*x_2*x_3*x_4*x_5
    &[24, -28, -26, 30, -25, 29, 27, -31],
    // x_1*x_4*x_5 - x_1*x_3*x_4*x_5 - x_1*x_2*x_4*x_5 + x_1*x_2*x_3*x_4*x_5
    &[25, -29, -27, 31],
    // x_2*x_4*x_5 - x_2*x_3*x_4*x_5 - x_1*x_2*x_4*x_5 + x_1*x_2*x_3*x_4*x_5
    &[26, -30, -27, 31],
    // x_1*x_2*x_4*x_5 - x_1*x_2*x_3*x_4*x_5
    &[27, -31],
    // x_3*x_4*x_5 - x_2*x_3*x_4*x_5 - x_1*x_3*x_4*x_5 + x_1*x_2*x_3*x_4*x_5
    &[28, -30, -29, 31],
    // x_1*x_3*x_4*x_5 - x_1*x_2*x_3*x_4*x_5
    &[29, -31],
    // x_2*x_3*x_4*x_5 - x_1*x_2*x_3*x_4*x_5
    &[30, -31],
    // x_1*x_2*x_3*x_4*x_5
    &[31],
];

/// This is an implementation of `GenMultiBitSort` (Algorithm 11) described in:
/// "An Efficient Secure Three-Party Sorting Protocol with an Honest Majority"
/// by K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, N. Kiribuchi, and B. Pinkas
/// <https://eprint.iacr.org/2019/695.pdf>.
///
/// Protocol to compute a secret sharing of a permutation, after sorting on multiple bits `num_multi_bits`.
/// At a high level, the protocol works as follows:
/// 1. Start with a vector of list of `L*n` secret shares `[[x1_1 ... x1_n], .. , [xL_1 ... xL_n]]` where each is a secret sharing of either zero or one.
///    Here, L is the number of multi bits which are processed together (`num_multi_bits`) and n is the number of records
/// 2. Equality Bit Checker : For j in 0 to 2 pow `num_multi_bits`
///    i. Get binary representation of j (B1 .. BL)
///    ii. For i in `num_multi_bits`
///      a. Locally compute `mult_inputs` as (Bi * `xi_j` + (1-Bi)(1- `xi_j`))
///   iii. Multiply all `mult_inputs` for this j
/// 3. Compute accumulated sum: For j in 0 to 2 pow `num_multi_bits`
///    i. For each record
///       a. Calculate accumulated `prefix_sum` = s + `mult_output`
/// 4. Compute the final output using sum of products executed in parallel for each record.
#[allow(dead_code)]
pub async fn multi_bit_permutation<'a, F: Field, S: SecretSharing<F>, C: Context<F, Share = S>>(
    ctx: C,
    input: &[Vec<S>],
) -> Result<Vec<S>, Error> {
    let num_multi_bits = input.len();
    assert!(num_multi_bits > 0);
    if num_multi_bits == 1 {
        return bit_permutation(ctx, &input[0]).await;
    }
    let num_records = input[0].len();
    let num_possible_bit_values = 2 << (num_multi_bits - 1);

    let share_of_one = ctx.share_of_one();

    // Equality bit checker: this checks if each secret shared record is equal to any of numbers between 0 and num_possible_bit_values
    let mut equality_check_futures = Vec::with_capacity(num_records);
    for i in 0..num_records {
        equality_check_futures.push(check_everything(ctx.clone(), i, input));
    }
    let equality_checks = try_join_all(equality_check_futures).await?;

    // Compute accumulated sum
    let mut prefix_sum = Vec::with_capacity(num_records);
    let mut cumulative_sum = S::ZERO;
    for bit_idx in 0..num_possible_bit_values {
        for record_idx in 0..num_records {
            if bit_idx == 0 {
                prefix_sum.push(Vec::with_capacity(num_multi_bits));
            }
            cumulative_sum += &equality_checks[record_idx][bit_idx];
            prefix_sum[record_idx].push(cumulative_sum.clone());
        }
    }

    // Take sum of products of output of equality check and accumulated sum
    let mut one_off_permutation =
        try_join_all((0..num_records).zip(repeat(ctx)).map(|(rec, ctx)| {
            let mut sop_inputs = Vec::with_capacity(num_possible_bit_values);
            for idx in 0..num_possible_bit_values {
                sop_inputs.push((&equality_checks[rec][idx], &prefix_sum[rec][idx]));
            }
            async move {
                ctx.sum_of_products(RecordId::from(rec), sop_inputs.as_slice())
                    .await
            }
        }))
        .await?;
    // we are subtracting "1" from the result since this protocol returns 1-index permutation whereas all other
    // protocols expect 0-indexed permutation
    for permutation in &mut one_off_permutation {
        *permutation -= &share_of_one;
    }
    Ok(one_off_permutation)
}

///
/// This function accepts a sequence of N secret-shared bits.
/// When considered as a bitwise representation of an N-bit unsigned number, it's clear that there are exactly
/// `2^N` possible values this could have.
/// This function checks all of these possible values, and returns a vector of secret-shared results.
/// Only one result will be a secret-sharing of one, all of the others will be secret-sharings of zero.
async fn check_everything<F, C, S>(
    ctx: C,
    record_idx: usize,
    input: &[Vec<S>],
) -> Result<Vec<S>, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    let record_id = RecordId::from(record_idx);
    let num_bits = input.len();
    //
    // Every equality check can be computed as a linear combination of coefficients.
    // For example, if we are given a 3-bit number `[x_3, x_2, x_1]`,
    // we can check if it is equal to 4, by computing:
    // `x_3 - x_2*x_3 - x_1*x_3 + x_1*x_2*x_3`
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
    let mut precomputed_combinations = Vec::with_capacity(1 << num_bits);
    precomputed_combinations.push(ctx.share_of_one());
    #[allow(clippy::needless_range_loop)]
    for bit_idx in 0..num_bits {
        let bit = &input[bit_idx][record_idx];
        let step = 1 << bit_idx;
        let num_children_to_add = precomputed_combinations.len();
        precomputed_combinations.push(bit.clone());
        if bit_idx == 0 {
            continue;
        }
        let mut multiplication_futures = Vec::with_capacity(num_children_to_add - 1);
        #[allow(clippy::needless_range_loop)]
        for j in 1..num_children_to_add {
            let child_idx = j + step;
            multiplication_futures.push(ctx.narrow(&BitOpStep::from(child_idx)).multiply(
                record_id,
                &precomputed_combinations[j],
                bit,
            ));
        }
        let mut multiplication_results = try_join_all(multiplication_futures).await?;
        precomputed_combinations.append(&mut multiplication_results);
    }

    // This loop just iterates over all the possible values this N-bit input could potentially represent
    // and checks if the bits are equal to this value. It does so my computing a linear combination of the
    // pre-computed coefficients.
    let mut equality_checks = Vec::with_capacity(1 << num_bits);
    for i in 0..(1 << num_bits) {
        equality_checks.push(check_equality_to(
            i,
            num_bits,
            precomputed_combinations.as_slice(),
        ));
    }
    Ok(equality_checks)
}

///
/// This function is used to generate the look-up tables saved as constants at the top of this file.
///
/// This function appears to be "unused" because it is only used to generate the constants.
#[allow(dead_code)]
fn generate_lookup_table(num_bits: usize) -> Vec<Vec<i8>> {
    let num_possible_values = 1 << num_bits;
    (0..num_possible_values)
        .map(|value| collect_coefficients_recursive(value, num_bits, 0, 0_i8))
        .collect()
}

///
/// Each row of the look-up tables saved as constants at the top of this file was generated via a call to this function.
/// Each row indicates which coefficients must be added / subtracted to check equality of an N-bit sequence to a specific value.
///
/// Let's work through an example:
/// To check if a 3-bit value is equal to `4`, we would logically compute:
/// `(x_3)(1 - x_2)(1 - x_1)`
/// This function basically just "multiplies that all out", distributing terms.
///
/// It starts with the least significant bit, `x_1`. If the value is equal to `4`, then the least significant bit should be equal to `0`
/// That is why the last term is `(1 - x_1)`.
/// Since there are two parts of this term, we need to distribute both of them, multiplying each element of the rest of the equation by each.
/// To do this, we recurse. We compute the rest of the equation times `1`, and subtract the rest of the equation times `x_1`.
/// Recall how the array of pre-computed linear-combinations is ordered:
/// `[1, x_1, x_2, x_1*x_2, x_3, x_1*x_3, x_2*x_3, x_1*x_2*x_3]`
/// It is ordered that way because we constructed it by:
/// ...iterating through the bits from least significant to most significant
/// ...and multiplying all values in the array by the next bit
/// ...thereby doubling the length of the array at each bit.
///
/// Think of this like a "tree". We start at the root node, (index 0). We begin with a value of `1`.
/// At depth=1 in the tree, we either multiply by `1`, or by `x_1`. Multiplication by `1` is easy, we just stay at the current index.
/// Multiplication by `x_1` is achieved by moving to the right by 1.
///
/// Then we go to the next bit, `x_2`. If the value is equal to `4`, then this bit should be equal to `0` as well.
/// That is why the second to last term is `(1 - x_2)`.
/// Once again, there are two parts of this term, and we need to distribute them both, multiplying each element of the rest of the equation by each.
/// To do this, we recurse yet again. We compute the rest of the equation times `1`, and subtract the rest of the equation times `x_2`.
/// Just like before, for each element, multiplying by "1" is achieved by just remaining that the current index in the pre-computed linear coefficients.
/// Now that we are at depth=2 in the tree, to find the value multiplied by `x_2` we must move to the index 2 to the right.
/// That's because there were only 2 elements in the array, and we multiplied each by `x_2`, resulting in an array of length 4.
///
/// Finally, we come to the most significant bit, `x_3`. If the value is equal to `4`, then this bit should be equal to `1`.
/// That is why we multiply by the term `(x_3)`.
/// There is only one component of this term, so we only need to recurse one time.
/// Now that we are at depth=3 in the tree, finding the value multiplied by `x_3` can be achieved by looking at the index 4 to the right in the array of pre-computed linear combinations.
/// That's because we took an array of length 4, and multiplied each value by `x_3`, appending the results to the end, resulting in an array of length 8.
fn collect_coefficients_recursive(
    value: u32,
    num_bits: usize,
    bit_idx: usize,
    current_coefficient_idx: i8,
) -> Vec<i8> {
    if bit_idx == num_bits {
        return vec![current_coefficient_idx];
    }
    let bit = (value >> bit_idx) & 1;
    let step = 1 << bit_idx;
    let next_bit_idx = bit_idx + 1;
    let times_x_coefficients = collect_coefficients_recursive(
        value,
        num_bits,
        next_bit_idx,
        current_coefficient_idx + step,
    );
    if bit == 0 {
        let times_one_coefficients =
            collect_coefficients_recursive(value, num_bits, next_bit_idx, current_coefficient_idx);
        return [
            times_one_coefficients,
            times_x_coefficients.iter().map(|x| -x).collect(),
        ]
        .concat();
    }
    times_x_coefficients
}

///
/// This function checks to see if a sequence of bits is a representation of a specific value.
/// It does so by computing a linear-combination of coefficients.
/// For example, to check if a 4-bit value is equal to 8, we would logically compute:
/// `(x_4)(1 - x_3)(1 - x_2)(1 - x_1)`
/// If you multiply this all out, that's equivalent to:
/// `x_4 - x_3*x_4 - x_2*x_4 + x_2*x_3*x_4 - x_1*x_4 + x_1*x_3*x_4 + x_1*x_2*x_4 - x_1*x_2*x_3*x_4`
/// /// All of these coefficients have been pre-computed and are stored in an array.
/// This function just looks up which coefficients are needed. In this case it would retrieve:
/// `[8, -12, -10, 14, -9, 13, 11, -15]`
/// The sign of each element indicates if that coefficient should be added or subtracted,
/// while the absolute value of the elements indicates the position in the array of pre-computed coefficients.
fn check_equality_to<F: Field, S: SecretSharing<F>>(
    value: usize,
    num_bits: usize,
    tree: &[S],
) -> S {
    let look_up_table = match num_bits {
        1 => COEFFICIENT_LOOK_UP_TABLE_ONE_BIT,
        2 => COEFFICIENT_LOOK_UP_TABLE_TWO_BITS,
        3 => COEFFICIENT_LOOK_UP_TABLE_THREE_BITS,
        4 => COEFFICIENT_LOOK_UP_TABLE_FOUR_BITS,
        5 => COEFFICIENT_LOOK_UP_TABLE_FIVE_BITS,
        _ => panic!("No lookup table has been generated for {num_bits} bits."),
    };
    let coefficients = look_up_table[value];
    coefficients.iter().fold(S::ZERO, |acc, x| {
        let x_abs = usize::try_from(x.abs()).unwrap();
        let next_value = &tree[x_abs];
        if *x < 0 {
            acc - next_value
        } else {
            acc + next_value
        }
    })
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use futures::future::try_join_all;

    use crate::{
        ff::{Field, Fp31},
        test_fixture::{Reconstruct, Runner, TestWorld},
        secret_sharing::SharedValue,
    };
    use super::multi_bit_permutation;

    use super::{check_everything, generate_lookup_table};
    const INPUT: [&[u128]; 3] = [
        &[0, 0, 1, 0, 1, 0],
        &[0, 1, 1, 0, 0, 0],
        &[1, 0, 1, 0, 1, 0],
    ];
    const EXPECTED: &[u128] = &[3, 2, 5, 0, 4, 1]; //100 010 111 000 101 000
    const EXPECTED_NUMS: &[usize] = &[4, 2, 7, 0, 5, 0];

    #[tokio::test]
    pub async fn semi_honest() {
        let world = TestWorld::new().await;

        let input: Vec<Vec<_>> = INPUT
            .into_iter()
            .map(|v| v.iter().map(|x| Fp31::from(*x)).collect())
            .collect();
        let result = world
            .semi_honest(input, |ctx, m_shares| async move {
                multi_bit_permutation(ctx, m_shares.as_slice())
                    .await
                    .unwrap()
            })
            .await;

        assert_eq!(&result.reconstruct(), EXPECTED);
    }

    #[tokio::test]
    pub async fn equality_checks() {
        let world = TestWorld::new().await;

        let input: Vec<Vec<_>> = INPUT
            .into_iter()
            .map(|v| v.iter().map(|x| Fp31::from(*x)).collect())
            .collect();

        let num_records = INPUT[0].len();

        let result = world
            .semi_honest(input, |ctx, m_shares| async move {
                let mut equality_check_futures = Vec::with_capacity(num_records);
                for i in 0..num_records {
                    let ctx = ctx.clone();
                    equality_check_futures.push(check_everything(ctx, i, m_shares.as_slice()));
                }
                try_join_all(equality_check_futures).await.unwrap()
            })
            .await;
        let reconstructs: Vec<Vec<Fp31>> = result.reconstruct();
        for (rec, row) in reconstructs.iter().enumerate() {
            for (j, check) in row.iter().enumerate() {
                if EXPECTED_NUMS[rec] == j {
                    assert_eq!(*check, Fp31::ONE);
                } else {
                    assert_eq!(*check, Fp31::ZERO);
                }
            }
        }
    }

    const COMMENT_KEY: [&str; 32] = [
        "1",
        "x_1",
        "x_2",
        "x_1*x_2",
        "x_3",
        "x_1*x_3",
        "x_2*x_3",
        "x_1*x_2*x_3",
        "x_4",
        "x_1*x_4",
        "x_2*x_4",
        "x_1*x_2*x_4",
        "x_3*x_4",
        "x_1*x_3*x_4",
        "x_2*x_3*x_4",
        "x_1*x_2*x_3*x_4",
        "x_5",
        "x_1*x_5",
        "x_2*x_5",
        "x_1*x_2*x_5",
        "x_3*x_5",
        "x_1*x_3*x_5",
        "x_2*x_3*x_5",
        "x_1*x_2*x_3*x_5",
        "x_4*x_5",
        "x_1*x_4*x_5",
        "x_2*x_4*x_5",
        "x_1*x_2*x_4*x_5",
        "x_3*x_4*x_5",
        "x_1*x_3*x_4*x_5",
        "x_2*x_3*x_4*x_5",
        "x_1*x_2*x_3*x_4*x_5",
    ];

    // This is used to generate the lookup tables of constants at the top of this file.
    #[ignore]
    #[test]
    pub fn generate_lookup_table_constants() {
        for i in 1..6 {
            let look_up_table = generate_lookup_table(i);
            println!("Lookup table for {i} bits: ");
            for row in look_up_table {
                let mut comment: String = "// ".to_owned();
                row.iter().enumerate().for_each(|(idx, x)| {
                    if idx > 0 {
                        if *x < 0 {
                            comment.push_str(" - ");
                        } else {
                            comment.push_str(" + ");
                        }
                    }
                    let index: usize = usize::try_from(x.abs()).unwrap();
                    comment.push_str(COMMENT_KEY[index]);
                });
                println!("    {comment}");
                println!("    &{row:?},");
            }
        }
        panic!();
    }
}
