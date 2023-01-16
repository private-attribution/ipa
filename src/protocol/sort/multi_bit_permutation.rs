use std::iter::repeat;

use crate::{
    error::Error,
    ff::Field,
    protocol::{context::Context, BitOpStep, RecordId},
    secret_sharing::SecretSharing,
};

use futures::future::try_join_all;

const P: i8 = 1;
const N: i8 = -1;
const COEFFICIENT_LOOK_UP_TABLE: [[i8; 16]; 16] = [
    [P, N, N, P, N, P, P, N, N, P, P, N, P, N, N, P],
    [0, P, 0, N, 0, N, 0, P, 0, N, 0, P, 0, P, 0, N],
    [0, 0, P, N, 0, 0, N, P, 0, 0, N, P, 0, 0, P, N],
    [0, 0, 0, P, 0, 0, 0, N, 0, 0, 0, N, 0, 0, 0, P],
    [0, 0, 0, 0, P, N, N, P, 0, 0, 0, 0, N, P, P, N],
    [0, 0, 0, 0, 0, P, 0, N, 0, 0, 0, 0, 0, N, 0, P],
    [0, 0, 0, 0, 0, 0, P, N, 0, 0, 0, 0, 0, 0, N, P],
    [0, 0, 0, 0, 0, 0, 0, P, 0, 0, 0, 0, 0, 0, 0, N],
    [0, 0, 0, 0, 0, 0, 0, 0, P, N, N, P, N, P, P, N],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, P, 0, N, 0, N, 0, P],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, P, N, 0, 0, N, P],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, P, 0, 0, 0, N],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, P, N, N, P],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, P, 0, N],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, P, N],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, P],
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
    let num_records = input[0].len();
    let num_possible_bit_values = 2 << (num_multi_bits - 1);

    let share_of_one = ctx.share_of_one();

    // Equality bit checker: this checks if each secret shared record is equal to any of numbers between 0 and num_possible_bit_values
    let equality_checks = try_join_all(
        (0..num_records)
            .zip(repeat(ctx.clone()))
            .map(|(i, ctx)| check_everything(ctx, i, input)),
    )
    .await?;

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
    let num_bits = input.len();

    let precomputed_combinations =
        pregenerate_all_combinations(ctx, record_idx, input, num_bits).await?;

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
    input: &[Vec<S>],
    num_bits: usize,
) -> Result<Vec<S>, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    let record_id = RecordId::from(record_idx);
    let mut precomputed_combinations = Vec::with_capacity(1 << num_bits);
    precomputed_combinations.push(ctx.share_of_one());
    for (bit_idx, column) in input.iter().enumerate() {
        let bit = &column[record_idx];
        let step = 1 << bit_idx;
        let num_children_to_add = precomputed_combinations.len();
        precomputed_combinations.push(bit.clone());
        if bit_idx == 0 {
            continue;
        }
        let mut multiplication_results = try_join_all(
            precomputed_combinations
                .iter()
                .enumerate()
                .skip(1)
                .take(num_children_to_add - 1)
                .map(|(j, precomputed_combination)| {
                    let child_idx = j + step;
                    ctx.narrow(&BitOpStep::from(child_idx)).multiply(
                        record_id,
                        precomputed_combination,
                        bit,
                    )
                }),
        )
        .await?;
        precomputed_combinations.append(&mut multiplication_results);
    }
    Ok(precomputed_combinations)
}

///
/// This function is used to generate the look-up tables saved as constants at the top of this file.
/// This function appears to be "unused" because it is only used to generate the constants.
///
/// Observe that the coefficients necessary to compute a given equality check form a Sierpiński triangle
/// <https://en.wikipedia.org/wiki/Sierpi%C5%84ski_triangle#/media/File:Multigrade_operator_AND.svg>
/// The Sierpiński triangle can be generated iteratively using the simple formula:
/// $f(n+1) = f(n) XOR 2*f(n)$
/// where $f(0) = 1$
///
/// This produces the following sequence:
/// 1, 3, 5, 15, 17, 51, 85, 255, ...
/// Considering these as binary numbers, you'll see they produce the Sierpiński triangle
/// 00000001
/// 00000011
/// 00000101
/// 00001111
/// 00010001
/// 00110011
/// 01010101
/// 11111111
///
/// In our case, we just have to reverse the order of the rows, so that the final one comes first,
/// and represents the coefficients used to compute equality to zero.
///
/// The signs of the coefficients are a bit more complex. Martin Thomson has observed that they follow
/// the following pattern:
///
/// 1. Take the row and column and bitwise AND them: $(i & j)$
/// 2. Count the number of non-zero bits in the result
/// 3. If the result is an odd number, the coefficient is negative. If the result is even, the coefficient is positive.
#[allow(dead_code)]
fn generate_lookup_table(num_bits: usize) -> Vec<Vec<i8>> {
    let side_length = 1 << num_bits;
    let mut sterpinski_triangle = Vec::with_capacity(side_length);
    for _ in 0..side_length {
        sterpinski_triangle.push(Vec::with_capacity(side_length));
    }
    let mut binary_representation = 1;
    for i in 0..side_length {
        if i > 0 {
            binary_representation = binary_representation ^ (binary_representation << 1);
        }
        let bits = get_big_endian_bits(binary_representation, side_length);
        for (j, bit) in bits.iter().enumerate() {
            let rows_from_bottom = side_length - i - 1;
            let sign = 1 - 2 * i8::try_from((j & i).count_ones() & 1).unwrap();

            sterpinski_triangle[rows_from_bottom].push(bit * sign);
        }
    }
    sterpinski_triangle
}

fn get_big_endian_bits(value: usize, num_bits: usize) -> Vec<i8> {
    let mut output = Vec::with_capacity(num_bits);
    for i in 0..num_bits {
        let bit = (value >> i) & 1;
        output.push(i8::from(bit != 0));
    }
    output.reverse();
    output
}

///
/// This function checks to see if a sequence of bits is a representation of a specific value.
/// It does so by computing a linear-combination of coefficients.
/// For example, to check if a 4-bit value is equal to 8, we would logically compute:
/// `(x_4)(1 - x_3)(1 - x_2)(1 - x_1)`
/// If you multiply this all out, that's equivalent to:
/// `x_4 - x_3*x_4 - x_2*x_4 + x_2*x_3*x_4 - x_1*x_4 + x_1*x_3*x_4 + x_1*x_2*x_4 - x_1*x_2*x_3*x_4`
///
/// All of these coefficients have been pre-computed and are stored in an array.
/// This function just looks up which coefficients are needed. In this case it would retrieve:
/// `[0, 0, 0, 0, 0, 0, 0, 0, 1, -1, -1, 1, -1, 1, 1, -1],`
/// The sign of each element indicates if that coefficient should be added or subtracted.
fn check_equality_to<F: Field, S: SecretSharing<F>>(
    value: usize,
    num_bits: usize,
    tree: &[S],
) -> S {
    debug_assert!(num_bits <= 4, "Lookup table only supports up to 4 bits");
    let coefficients = &COEFFICIENT_LOOK_UP_TABLE[value];
    coefficients
        .iter()
        .zip(tree)
        .fold(S::ZERO, |acc, (coef, value)| {
            if *coef == P {
                acc + value
            } else if *coef == N {
                acc - value
            } else {
                acc
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

    // This is used to generate the lookup tables of constants at the top of this file.
    #[ignore]
    #[test]
    pub fn generate_lookup_table_constants() {
        let look_up_table = generate_lookup_table(4);
        for row in look_up_table {
            println!(
                "    [{}],",
                row.iter()
                    .map(|x| if *x == 1 {
                        "P"
                    } else if *x == -1 {
                        "N"
                    } else {
                        "0"
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        panic!();
    }
}
