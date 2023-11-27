use std::iter::{repeat, zip};

use embed_doc_image::embed_doc_image;

use crate::{
    error::Error,
    ff::Field,
    protocol::{context::Context, BasicProtocols, RecordId},
    secret_sharing::{Linear as LinearSecretSharing, LinearRefOps},
};

#[embed_doc_image("bit_permutation", "images/sort/bit_permutations.png")]
/// This is an implementation of `GenBitPerm` (Algorithm 3) described in:
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
pub async fn bit_permutation<
    'a,
    F: Field,
    S: LinearSecretSharing<F> + BasicProtocols<C, F>,
    C: Context,
>(
    ctx: C,
    input: &[S],
) -> Result<Vec<S>, Error>
where
    for<'r> &'r S: LinearRefOps<'r, S, F>,
{
    let ctx_ref = &ctx;
    let ctx = ctx.set_total_records(2 * input.len());
    let share_of_one = S::share_known_value(&ctx, F::ONE);

    let mult_input = zip(repeat(share_of_one.clone()), input)
        .map(|(one, x)| one - x)
        .chain(input.iter().cloned())
        .scan(S::ZERO, |sum, x| {
            *sum += &x;
            Some((x, sum.clone()))
        });

    let async_multiply =
        zip(repeat(ctx), mult_input)
            .enumerate()
            .map(|(i, (ctx, (x, sum)))| async move {
                let record_id = RecordId::from(i);
                x.multiply(&sum, ctx, record_id).await
            });
    let mut mult_output = ctx_ref.try_join(async_multiply).await?;

    debug_assert!(mult_output.len() == input.len() * 2);
    // Generate permutation location
    let len = mult_output.len() / 2;
    for i in 0..len {
        // we are subtracting "1" from the result since this protocol returns 1-index permutation whereas all other
        // protocols expect 0-indexed permutation
        let less_one = &mult_output[i + len] - &share_of_one;
        mult_output[i] = less_one + &mult_output[i];
    }
    mult_output.truncate(len);
    Ok(mult_output)
}

#[cfg(all(test, unit_test))]
mod tests {
    use crate::{
        ff::{Field, Fp31},
        protocol::sort::bit_permutation::bit_permutation,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    // With this input, for stable sort we expect all 0's to line up before 1's.
    // The expected sort order is same as expected_sort_output.
    const INPUT: &[u128] = &[1, 0, 1, 0, 0, 1, 0];
    const EXPECTED: &[u128] = &[4, 0, 5, 1, 2, 6, 3];

    #[tokio::test]
    pub async fn semi_honest() {
        let world = TestWorld::default();

        let input: Vec<_> = INPUT.iter().map(|x| Fp31::truncate_from(*x)).collect();
        let result = world
            .semi_honest(input.into_iter(), |ctx, m_shares| async move {
                bit_permutation(ctx, &m_shares).await.unwrap()
            })
            .await;

        assert_eq!(&result.reconstruct(), EXPECTED);
    }

    #[tokio::test]
    pub async fn malicious() {
        let world = TestWorld::default();

        let input: Vec<_> = INPUT.iter().map(|x| Fp31::truncate_from(*x)).collect();
        let result = world
            .upgraded_malicious(input.into_iter(), |ctx, m_shares| async move {
                bit_permutation(ctx, &m_shares).await.unwrap()
            })
            .await;

        assert_eq!(&result.reconstruct(), EXPECTED);
    }
}
