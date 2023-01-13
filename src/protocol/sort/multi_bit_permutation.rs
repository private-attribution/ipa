use std::iter::repeat;

use crate::{
    error::Error,
    ff::Field,
    protocol::{context::Context, sort::bit_permutation::bit_permutation, BitOpStep, RecordId},
    secret_sharing::SecretSharing,
};

use futures::future::try_join_all;

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
    let mut step = 1 << num_bits;
    let mut precomputed_combinations = vec![S::ZERO; step];
    for bit_idx in 0..num_bits {
        let bit = &input[num_bits - bit_idx - 1][record_idx];
        step >>= 1;
        if bit_idx == 0 {
            precomputed_combinations[0] = ctx.share_of_one();
            precomputed_combinations[step] = bit.clone();
        } else {
            let num_children_to_add = 1 << bit_idx;
            let mut multiplication_futures = Vec::with_capacity(num_children_to_add - 1);
            for j in 1..num_children_to_add {
                let parent_idx = 2 * j * step;
                let child_idx = parent_idx + step;
                let parent = &precomputed_combinations[parent_idx];
                multiplication_futures.push(
                    ctx.narrow(&BitOpStep::from(child_idx))
                        .multiply(record_id, parent, bit),
                );
            }
            let multiplication_results = try_join_all(multiplication_futures).await?;
            precomputed_combinations[step] = (*bit).clone();
            for (j, mult_result) in multiplication_results.into_iter().enumerate() {
                precomputed_combinations[step * (2 * (j + 1) + 1)] = mult_result;
            }
        }
    }

    let mut equality_checks = Vec::with_capacity(1 << num_bits);
    for i in 0..(1 << num_bits) {
        equality_checks.push(check_equality_to(
            i,
            num_bits,
            0,
            1_i8,
            precomputed_combinations.as_slice(),
        ));
    }
    Ok(equality_checks)
}

fn check_equality_to<F: Field, S: SecretSharing<F>>(
    value: u32,
    bit_number: usize,
    idx: usize,
    sign: i8,
    precomputed_combinations: &[S],
) -> S {
    if bit_number == 0 {
        if sign == 1_i8 {
            return precomputed_combinations[idx].clone();
        }
        return -precomputed_combinations[idx].clone();
    }
    let bit = (value >> (bit_number - 1)) & 1;
    let half_step = 1 << (bit_number - 1);
    if bit == 0 {
        let left = check_equality_to(value, bit_number - 1, idx, sign, precomputed_combinations);
        let right = check_equality_to(
            value,
            bit_number - 1,
            idx + half_step,
            -sign,
            precomputed_combinations,
        );
        return left + &right;
    }
    check_equality_to(
        value,
        bit_number - 1,
        idx + half_step,
        sign,
        precomputed_combinations,
    )
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

    use super::check_everything;
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
}
