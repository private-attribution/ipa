use crate::{
    error::Error,
    ff::Field,
    protocol::{
        context::Context,
        sort::{check_everything, pregenerate_all_combinations},
        BasicProtocols, RecordId,
    },
    secret_sharing::Linear as LinearSecretSharing,
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
pub async fn multi_bit_permutation<
    'a,
    F: Field,
    S: LinearSecretSharing<F> + BasicProtocols<C, F>,
    C: Context,
>(
    ctx: C,
    input: &[Vec<S>],
) -> Result<Vec<S>, Error> {
    let num_records = input.len();
    assert!(num_records > 0);

    let num_multi_bits = (input[0]).len();
    assert!(num_multi_bits > 0);

    let num_possible_bit_values = 1 << num_multi_bits;

    let share_of_one = S::share_known_value(&ctx, F::ONE);
    // Equality bit checker: this checks if each secret shared record is equal to any of numbers between 0 and num_possible_bit_values
    let equality_checks = try_join_all(
        input
            .iter()
            .zip(repeat(ctx.set_total_records(num_records)))
            .enumerate()
            .map(|(idx, (record, ctx))| async move {
                let pregenerated_combinations =
                    pregenerate_all_combinations(ctx, idx, record).await?;
                Ok::<_, Error>(check_everything(
                    &pregenerated_combinations,
                    num_possible_bit_values,
                ))
            }),
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
                S::sum_of_products(
                    ctx,
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

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use futures::future::try_join_all;

    use super::multi_bit_permutation;
    use crate::{
        ff::{Field, Fp31},
        protocol::{
            context::Context,
            sort::{check_everything, pregenerate_all_combinations},
        },
        secret_sharing::SharedValue,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

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
        let world = TestWorld::default();

        let input: Vec<Vec<_>> = INPUT
            .into_iter()
            .map(|v| v.iter().map(|x| Fp31::truncate_from(*x)).collect())
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
        let world = TestWorld::default();

        let input: Vec<Vec<_>> = INPUT
            .into_iter()
            .map(|v| v.iter().map(|x| Fp31::truncate_from(*x)).collect())
            .collect();

        let num_records = INPUT.len();

        let result = world
            .semi_honest(input, |ctx, m_shares| async move {
                let mut equality_check_futures = Vec::with_capacity(num_records);
                for (i, record) in m_shares.iter().enumerate() {
                    let ctx = ctx.set_total_records(num_records);
                    let pregenerated_combos = pregenerate_all_combinations(ctx, i, record);
                    equality_check_futures.push(pregenerated_combos);
                }
                let pregen_combos = try_join_all(equality_check_futures).await.unwrap();
                pregen_combos
                    .iter()
                    .map(|x| check_everything(x, 8))
                    .collect::<Vec<_>>()
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
