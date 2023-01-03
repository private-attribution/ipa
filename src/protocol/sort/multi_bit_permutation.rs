use crate::{
    error::Error,
    ff::Field,
    protocol::{boolean::multiply_all_shares, context::Context, RecordId},
    secret_sharing::SecretSharing,
};

use embed_doc_image::embed_doc_image;

#[embed_doc_image("multi_bit_permutation", "images/sort/bit_permutations.png")]
/// This is an implementation of `GenMultiBitSort` (Algorithm 11) described in:
/// "An Efficient Secure Three-Party Sorting Protocol with an Honest Majority"
/// by K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, N. Kiribuchi, and B. Pinkas
/// <https://eprint.iacr.org/2019/695.pdf>.
///
/// Protocol to compute a secret sharing of a permutation, after sorting on just one bit.
/// At a high level, the protocol works as follows:
/// 1. Start with a list of `n` secret shares `[x_1]` ... `[x_n]` where each is a secret sharing of either zero or one.
/// 2. Create a vector of length `2*n` where the first `n` rows have the values `[1 - x_1]` ... `[1 - x_n]`
/// and the next `n` rows have the value `[x_1]` ... `[x_n]`
/// 3. Compute a new vector of length `2*n` by computing the running sum of the vector from step 2.
/// 4. Compute another vector of length `2*n` by multipling the vectors from steps 2 and 3 element-wise.
/// 5. Compute the final output, a vector of length `n`. Each element `i` in this output vector is the sum of
/// the elements at index `i` and `i+n` from the vector computed in step 4.
///
/// ![Bit Permutation steps][bit_permutation]
/// ## Panics
/// In case the function is unable to get double size of output from multiplication step, the code will panic
///
/// ## Errors
/// It will propagate errors from multiplication protocol.
#[allow(dead_code)]
pub async fn multi_bit_permutation_single<
    'a,
    F: Field,
    S: SecretSharing<F>,
    C: Context<F, Share = S>,
>(
    ctx: C,
    input: &[Vec<S>],
    l_el: usize,
) -> Result<Vec<S>, Error> {
    assert_eq!(input.len(), l_el);
    let share_of_one = ctx.share_of_one();
    let num_inputs = input[0].len();
    let twonminusone = 2 << l_el - 1;
    let mut rec_no:usize = 0;
    let mut f = Vec::with_capacity(twonminusone);
    for j in 0..twonminusone {
        let b_bee = get_binary_from_int(j, l_el);
        let mut d_dee = Vec::with_capacity(l_el);
        for i in 0..l_el {
            // val has ith bit records or negative ith bit
            if !b_bee[i] {
                d_dee.push(
                    input[i]
                        .iter()
                        .map(|v| -v.clone() + &share_of_one)
                        .collect::<Vec<_>>(),
                );
            } else {
                d_dee.push(input[i].to_vec());
            }
        }
        // multiply all D's for this j for each record => f(j)
        let mut out = Vec::new();
        for rec in 0..num_inputs {
            let mut abc = Vec::new();
            for k in 0..l_el {
                abc.push(d_dee[k][rec].clone());
            }
            out.push(
                multiply_all_shares(
                    ctx.narrow("multiply_across_bits"),
                    RecordId::from(rec_no),
                    abc.as_slice(),
                )
                .await?,
            );
            rec_no += 1;
        }
        f.push(out);
    }

    let mut sum_local = S::ZERO;
    let mut total_sums = Vec::new();
    for j in 0..twonminusone {
        let mut sum = Vec::new();
        for rec in 0..l_el {
            sum_local += &f[j][rec];
            sum.push(sum_local.clone());
        }
        total_sums.push(sum);
    }
    let mut futures = Vec::new();
    for rec in 0..l_el {
        let mut accumulatea = Vec::new();
        let mut accumulateb = Vec::new();

        for j in 0..twonminusone {
            accumulatea.push(&f[j][rec]);
            accumulateb.push(&total_sums[j][rec]);
        }
        futures.push(
            ctx.narrow("sop")
                .sum_of_products(
                    RecordId::from(rec),
                    accumulatea.as_slice(),
                    accumulateb.as_slice(),
                )
                .await?,
        );
    }
    Ok(futures)
}

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
        protocol::{
            sort::multi_bit_permutation::{get_binary_from_int, multi_bit_permutation_single},
        },
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    const INPUT2: [&[u128]; 2] = [&[1, 0], &[1, 0]];
    const EXPECTED2: &[u128] = &[2, 1];

    #[tokio::test]
    pub async fn semi_honest() {
        let world = TestWorld::new().await;

        let input: Vec<Vec<_>> = INPUT2
            .into_iter()
            .map(|v| v.into_iter().map(|x| Fp31::from(*x)).collect())
            .collect();
        let result = world
            .semi_honest(input, |ctx, m_shares| async move {
                multi_bit_permutation_single(ctx, m_shares.as_slice(), 2)
                    .await
                    .unwrap()
            })
            .await;

        assert_eq!(&result.reconstruct(), EXPECTED2);
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
