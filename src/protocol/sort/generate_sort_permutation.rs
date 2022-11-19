use crate::{
    error::BoxError,
    ff::Field,
    protocol::{
        context::ProtocolContext,
        modulus_conversion::convert_shares::convert_shares_for_a_bit,
        sort::bit_permutation::bit_permutation,
        sort::SortStep::{ApplyInv, BitPermutationStep, ComposeStep, ModulusConversion},
        IpaProtocolStep::Sort,
    },
    secret_sharing::Replicated,
};

use super::{compose::compose, secureapplyinv::secureapplyinv};
use embed_doc_image::embed_doc_image;

/// This is an implementation of `GenPerm` (Algorithm 6) described in:
/// "An Efficient Secure Three-Party Sorting Protocol with an Honest Majority"
/// by K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, N. Kiribuchi, and B. Pinkas
/// <https://eprint.iacr.org/2019/695.pdf>.

#[allow(dead_code)]
#[embed_doc_image("semi_honest_sort", "images/sort/semi-honest-sort.png")]
/// This protocol generates permutation of a stable sort for the given shares of inputs.
/// ![Generate sort permutation steps][semi_honest_sort]
/// Steps
/// For the 0th bit
/// 1. Get replicated shares in Field using modulus conversion
/// 2. Compute bit permutation that sorts 0th bit
/// For 1st to N-1th bit of input share
/// 1. Get replicated shares in Field using modulus conversion
/// 2. Sort ith bit based on i-1th bits by applying i-1th composition on ith bit
/// 3  Compute bit permutation that sorts ith bit
/// 4. Compute ith composition by composing i-1th composition on ith permutation
/// In the end, n-1th composition is returned. This is the permutation which sorts the inputs
pub async fn generate_sort_permutation<'a, F: Field>(
    ctx: ProtocolContext<'_, Replicated<F>, F>,
    input: &'a [(u64, u64)],
    num_bits: u8,
) -> Result<Vec<Replicated<F>>, BoxError> {
    let ctx_0 = ctx.narrow(&Sort(0));
    let bit_0 =
        convert_shares_for_a_bit(ctx_0.narrow(&ModulusConversion), input, num_bits, 0).await?;
    let bit_0_permutation = bit_permutation(ctx_0.narrow(&BitPermutationStep), &bit_0).await?;

    let mut composed_less_significant_bits_permutation = bit_0_permutation;
    for bit_num in 1..num_bits {
        let ctx_bit = ctx.narrow(&Sort(bit_num));
        let bit_i =
            convert_shares_for_a_bit(ctx_bit.narrow(&ModulusConversion), input, num_bits, bit_num)
                .await?;
        let bit_i_sorted_by_less_significant_bits = secureapplyinv(
            ctx_bit.narrow(&ApplyInv),
            bit_i,
            composed_less_significant_bits_permutation.clone(),
        )
        .await?;

        let bit_i_permutation = bit_permutation(
            ctx_bit.narrow(&BitPermutationStep),
            &bit_i_sorted_by_less_significant_bits,
        )
        .await?;
        let composed_i_permutation = compose(
            ctx_bit.narrow(&ComposeStep),
            composed_less_significant_bits_permutation,
            bit_i_permutation,
        )
        .await?;
        composed_less_significant_bits_permutation = composed_i_permutation;
    }
    Ok(composed_less_significant_bits_permutation)
}

#[cfg(test)]
mod tests {
    use crate::error::BoxError;
    use crate::test_fixture::sort::execute_sort;

    #[tokio::test]
    pub async fn test_generate_sort_permutation() -> Result<(), BoxError> {
        execute_sort().await
    }
}
