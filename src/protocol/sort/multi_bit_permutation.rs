use crate::{
    error::Error,
    ff::Field,
    protocol::{
        boolean::multiply_all_shares,
        context::Context,
        sort::MultiBitPermutationStep::{MultiplyAcrossBits, Sop},
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
/// 2. For j in 0 to 2 pow `num_multi_bits`
///    i. Get binary representation of j (B1 .. BL)
///    ii. For i in `num_multi_bits`
///      a. Locally compute `mult_inputs` as (Bi * `xi_j` + (1-Bi)(1- `xi_j`))
///   iii. Multiply all `mult_inputs` for this j
/// 4. For j in 0 to 2 pow `num_multi_bits`
///    i. For each record
///       a. Calculate accumulated `total_sum` = s + `mult_output`
/// 5. Compute the final output using sum of products executed in parallel for each record.
#[allow(dead_code)]
pub async fn multi_bit_permutation_single<
    'a,
    F: Field,
    S: SecretSharing<F>,
    C: Context<F, Share = S>,
>(
    ctx: C,
    input: &[Vec<S>],
) -> Result<Vec<S>, Error> {
    let share_of_one = ctx.share_of_one();
    let num_multi_bits = input.len();
    let num_recs = input[0].len();
    let twonminusone = 2 << (num_multi_bits - 1);

    let mut mult_outputs = Vec::with_capacity(twonminusone);
    for j in 0..twonminusone {
        let j_bit_representation = get_binary_from_int(j, num_multi_bits);
        let mut mult_inputs = Vec::with_capacity(num_multi_bits);
        for i in 0..num_multi_bits {
            if j_bit_representation[i] {
                mult_inputs.push(input[i].clone());
            } else {
                mult_inputs.push(
                    input[i]
                        .iter()
                        .map(|v| -v.clone() + &share_of_one)
                        .collect::<Vec<_>>(),
                );
            }
        }
        // multiply all mult_inputs for this j for each record => f(j)
        let mut j_mult_output = Vec::new();
        for rec in 0..num_recs {
            let mut mult_inputs_all = Vec::new();
            for mult_input in mult_inputs.iter().take(num_multi_bits) {
                mult_inputs_all.push(mult_input[rec].clone());
            }
            j_mult_output.push(
                multiply_all_shares(
                    ctx.narrow(&MultiplyAcrossBits),
                    RecordId::from(j * num_recs + rec),
                    mult_inputs_all.as_slice(),
                )
                .await?,
            );
        }
        mult_outputs.push(j_mult_output);
    }

    let mut sum_local = S::ZERO;
    let mut total_sums = Vec::new();
    for mult_output in mult_outputs.iter().take(twonminusone) {
        let mut sum = Vec::new();
        for rec in mult_output.iter().take(num_recs) {
            sum_local += rec;
            sum.push(sum_local.clone());
        }
        total_sums.push(sum);
    }
    let mut permutation_futures = Vec::new();
    for rec in 0..num_recs {
        let mut mult_outputs_per_rec = Vec::new();
        let mut total_sums_per_rec = Vec::new();

        for j in 0..twonminusone {
            mult_outputs_per_rec.push(&mult_outputs[j][rec]);
            total_sums_per_rec.push(&total_sums[j][rec]);
        }
        let ctx_sop = ctx.narrow(&Sop);
        permutation_futures.push(async move {
            ctx_sop
                .sum_of_products(
                    RecordId::from(rec),
                    mult_outputs_per_rec.as_slice(),
                    total_sums_per_rec.as_slice(),
                )
                .await
        });
    }
    try_join_all(permutation_futures).await
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
    use crate::{
        ff::Fp31,
        protocol::sort::multi_bit_permutation::{
            get_binary_from_int, multi_bit_permutation_single,
        },
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    const INPUT: [&[u128]; 3] = [&[0, 1, 0, 1, 0], &[1, 1, 0, 0, 0], &[0, 1, 0, 1, 0]];
    const EXPECTED: &[u128] = &[3, 5, 1, 4, 2]; // 010 111 000 101 000

    #[tokio::test]
    pub async fn semi_honest() {
        let world = TestWorld::new().await;

        let input: Vec<Vec<_>> = INPUT
            .into_iter()
            .map(|v| v.iter().map(|x| Fp31::from(*x)).collect())
            .collect();
        let result = world
            .semi_honest(input, |ctx, m_shares| async move {
                multi_bit_permutation_single(ctx, m_shares.as_slice())
                    .await
                    .unwrap()
            })
            .await;

        assert_eq!(&result.reconstruct(), EXPECTED);
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
