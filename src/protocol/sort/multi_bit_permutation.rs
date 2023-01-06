use crate::{
    error::Error,
    ff::Field,
    protocol::{
        boolean::multiply_all_shares,
        context::Context,
        sort::MultiBitPermutationStep::{EqualityBitChecker, MultiplyAcrossBits, Sop},
        RecordId,
    },
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
///    Here, L is the number of multi bits which are procrssed together (`num_multi_bits`) and n is the number of records
/// 2. Equality Bit Checker : For j in 0 to 2 pow `num_multi_bits`
///    i. Get binary representation of j (B1 .. BL)
///    ii. For i in `num_multi_bits`
///      a. Locally compute `mult_inputs` as (Bi * `xi_j` + (1-Bi)(1- `xi_j`))
///   iii. Multiply all `mult_inputs` for this j
/// 3. Compute accumulated sum: For j in 0 to 2 pow `num_multi_bits`
///    i. For each record
///       a. Calculate accumulated `total_sum` = s + `mult_output`
/// 4. Compute the final output using sum of products executed in parallel for each record.
#[allow(dead_code)]
pub async fn multi_bit_permutation<'a, F: Field, S: SecretSharing<F>, C: Context<F, Share = S>>(
    ctx: C,
    input: &[Vec<S>],
) -> Result<Vec<S>, Error> {
    let num_multi_bits = input.len();
    let num_records = input[0].len();
    let num_possible_bit_values = 2 << (num_multi_bits - 1);

    // Equality bit checker: this checks if each secret shared record is equal to any of numbers between 0 and num_possible_bit_values
    let mut equality_check_futures = Vec::with_capacity(num_possible_bit_values * num_records);
    for j in 0..num_possible_bit_values {
        let ctx_equality_checker = ctx.narrow(&EqualityBitChecker);
        equality_check_futures
            .push(async move { get_bit_equality_checkers(j, input, ctx_equality_checker).await });
    }

    let equality_checks = try_join_all(equality_check_futures).await?;

    // Compute accumulated sum
    let mut sop_inputs_transposed = Vec::with_capacity(num_possible_bit_values * num_records);
    let mut initial_state = S::ZERO;
    for equality_check in equality_checks {
        let out = equality_check
            .into_iter()
            .scan(initial_state, |sum, x| {
                *sum += &x;
                Some((x, sum.clone()))
            })
            .collect::<Vec<_>>();
        initial_state = out
            .last()
            .unwrap_or_else(|| panic!("We should never reach here"))
            .1
            .clone();
        sop_inputs_transposed.push(out);
    }

    // Take sum of products of output of equality check and accumulated sum
    let mut permutation_futures = Vec::with_capacity(num_records);
    for rec in 0..num_records {
        let ctx_sop = ctx.narrow(&Sop);
        let mut sop_inputs = Vec::with_capacity(num_possible_bit_values);
        for sop_input_transposed in sop_inputs_transposed.iter().take(num_possible_bit_values) {
            sop_inputs.push((&sop_input_transposed[rec].0, &sop_input_transposed[rec].1));
        }
        permutation_futures.push(async move {
            ctx_sop
                .sum_of_products(RecordId::from(rec), sop_inputs.as_slice())
                .await
        });
    }
    try_join_all(permutation_futures).await
}

/// For a given `idx` check if each of the record has same value as idx.
/// Steps
/// 1. Get bit representation of `idx`
/// 2. Calculate equality check
///   i. keep record bit if `idx` bit is 1
///   ii.toggle record bit if idx bit is 0 (Done by taking `share_of_one` - value)
/// 3. Multiply equality checks for all bits per record - in clear per record this will be 1 only for 1 index while 0 for all others
async fn get_bit_equality_checkers<F, C, S>(
    idx: usize,
    input: &[Vec<S>],
    ctx: C,
) -> Result<Vec<S>, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    let num_multi_bits = input.len();
    let num_records = input[0].len();

    let mut equality_check_futures = Vec::with_capacity(num_records);

    let j_bit_representation = get_binary_from_int(idx, num_multi_bits);

    for rec in 0..num_records {
        let ctx_across_bits = ctx.narrow(&MultiplyAcrossBits);
        let share_of_one = ctx_across_bits.share_of_one();

        let mut bits_for_record = Vec::with_capacity(num_multi_bits);
        for jth_bits in input.iter().take(num_multi_bits) {
            bits_for_record.push(jth_bits[rec].clone());
        }
        let mut mult_input = Vec::with_capacity(num_multi_bits);
        for jth_bit in j_bit_representation.iter().take(num_multi_bits) {
            if *jth_bit {
                mult_input.push(bits_for_record.remove(0));
            } else {
                mult_input.push(-bits_for_record.remove(0) + &share_of_one);
            }
        }
        equality_check_futures.push(async move {
            // multiply all mult_input for this j for each record => f(j)
            multiply_all_shares(
                ctx_across_bits,
                RecordId::from(idx * num_records + rec),
                mult_input.as_slice(),
            )
            .await
        });
    }
    try_join_all(equality_check_futures).await
}

/// Get binary representation of an integer as a vector of bool
fn get_binary_from_int(input_num: usize, num_bits: usize) -> Vec<bool> {
    let mut num = input_num;
    let mut bits = Vec::with_capacity(num_bits);
    while num != 0 {
        bits.push(num & 1 == 1);
        num >>= 1;
    }
    bits.resize_with(num_bits, Default::default);
    bits.reverse();
    bits
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use futures::future::try_join_all;

    use crate::{
        ff::{Field, Fp31},
        protocol::{
            context::Context,
            sort::{
                multi_bit_permutation::{
                    get_binary_from_int, get_bit_equality_checkers, multi_bit_permutation,
                },
                MultiBitPermutationStep::EqualityBitChecker,
            },
        },
        test_fixture::{Reconstruct, Runner, TestWorld},
    };
    const INPUT: [&[u128]; 3] = [
        &[1, 0, 1, 0, 1, 0],
        &[0, 1, 1, 0, 0, 0],
        &[0, 0, 1, 0, 1, 0],
    ];
    const EXPECTED: &[u128] = &[4, 3, 6, 1, 5, 2]; //100 010 111 000 101 000
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
    pub async fn bit_equality_checkers() {
        let world = TestWorld::new().await;

        let input: Vec<Vec<_>> = INPUT
            .into_iter()
            .map(|v| v.iter().map(|x| Fp31::from(*x)).collect())
            .collect();

        let num_multi_bits = INPUT.len();
        let num_records = INPUT[0].len();
        let num_possible_bit_values = 2 << (num_multi_bits - 1);

        let result = world
            .semi_honest(input, |ctx, m_shares| async move {
                let mut equality_check_futures =
                    Vec::with_capacity(num_possible_bit_values * num_records);
                for j in 0..num_possible_bit_values {
                    let ctx_equality_checker = ctx.narrow(&EqualityBitChecker);
                    let m_shares_copy = m_shares.clone();
                    equality_check_futures.push(async move {
                        get_bit_equality_checkers(j, &m_shares_copy, ctx_equality_checker).await
                    });
                }

                try_join_all(equality_check_futures).await.unwrap()
            })
            .await;
        let reconstructs = result.reconstruct();
        for (j, item) in reconstructs
            .iter()
            .enumerate()
            .take(num_possible_bit_values)
        {
            for rec in 0..num_records {
                if EXPECTED_NUMS[rec] == j {
                    assert_eq!(item[rec], Fp31::ONE);
                } else {
                    assert_eq!(item[rec], Fp31::ZERO);
                }
            }
        }
    }

    #[test]
    fn get_binary_from_int_basic() {
        assert_eq!(
            get_binary_from_int(1024, 12),
            vec![false, true, false, false, false, false, false, false, false, false, false, false]
        );
        assert_eq!(
            get_binary_from_int(127, 7),
            vec![true, true, true, true, true, true, true]
        );
        assert_eq!(
            get_binary_from_int(21, 5),
            vec![true, false, true, false, true]
        );
    }
}
