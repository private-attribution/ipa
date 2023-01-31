use crate::{
    error::Error,
    ff::Field,
    protocol::{context::Context, BitOpStep, RecordId},
    secret_sharing::{Arithmetic as ArithmeticSecretSharing, SecretSharing},
};
use futures::future::try_join_all;
use std::iter::repeat;

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
pub async fn multi_bit_permutation<
    'a,
    F: Field,
    S: ArithmeticSecretSharing<F>,
    C: Context<F, Share = S>,
>(
    ctx: C,
    input: &[Vec<S>],
) -> Result<Vec<S>, Error> {
    let num_records = input.len();
    assert!(num_records > 0);

    let num_multi_bits = (input[0]).len();
    assert!(num_multi_bits > 0);

    let num_possible_bit_values = 2 << (num_multi_bits - 1);

    let share_of_one = ctx.share_of_one();

    // Equality bit checker: this checks if each secret shared record is equal to any of numbers between 0 and num_possible_bit_values
    let equality_checks = try_join_all(
        input
            .iter()
            .zip(repeat(ctx.set_total_records(num_records)))
            .enumerate()
            .map(|(idx, (record, ctx))| check_everything(ctx, idx, record)),
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
    let mut one_off_permutation = try_join_all(
        equality_checks
            .into_iter()
            .zip(prefix_sum.into_iter())
            .zip(repeat(ctx.set_total_records(num_records)))
            .enumerate()
            .map(|(i, ((eq_checks, prefix_sums), ctx))| async move {
                ctx.sum_of_products(
                    RecordId::from(i),
                    eq_checks.as_slice(),
                    prefix_sums.as_slice(),
                )
                .await
            }),
    )
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
async fn check_everything<F, C, S>(ctx: C, record_idx: usize, record: &[S]) -> Result<Vec<S>, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: ArithmeticSecretSharing<F>,
{
    let num_bits = record.len();
    let precomputed_combinations =
        pregenerate_all_combinations(ctx, record_idx, record, num_bits).await?;

    // This loop just iterates over all the possible values this N-bit input could potentially represent
    // and checks if the bits are equal to this value. It does so my computing a linear combination of the
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
    let mut equality_checks = Vec::with_capacity(side_length);
    for i in 0..side_length {
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
        equality_checks.push(check);
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
    input: &[S],
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
    for (bit_idx, bit) in input.iter().enumerate() {
        let step = 1 << bit_idx;
        let mut multiplication_results =
            try_join_all(precomputed_combinations.iter().skip(1).enumerate().map(
                |(j, precomputed_combination)| {
                    let child_idx = j + step;
                    ctx.narrow(&BitOpStep::from(child_idx)).multiply(
                        record_id,
                        precomputed_combination,
                        bit,
                    )
                },
            ))
            .await?;
        precomputed_combinations.push(bit.clone());
        precomputed_combinations.append(&mut multiplication_results);
    }
    Ok(precomputed_combinations)
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use futures::future::try_join_all;

    use super::multi_bit_permutation;
    use crate::{
        ff::{Field, Fp31},
        protocol::context::Context,
        secret_sharing::SharedValue,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    use super::check_everything;

    const INPUT: [[u128; 3]; 6] = [
        [0, 0, 1],
        [0, 1, 0],
        [1, 1, 1],
        [0, 0, 0],
        [1, 0, 1],
        [0, 0, 0],
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
                multi_bit_permutation(ctx, &m_shares).await.unwrap()
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

        let num_records = INPUT.len();

        let result = world
            .semi_honest(input, |ctx, m_shares| async move {
                let mut equality_check_futures = Vec::with_capacity(num_records);
                for (i, record) in m_shares.iter().enumerate() {
                    let ctx = ctx.set_total_records(num_records);
                    equality_check_futures.push(check_everything(ctx, i, record));
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
}
