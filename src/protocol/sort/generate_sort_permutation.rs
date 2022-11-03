use crate::{
    error::BoxError,
    ff::Field,
    protocol::{
        context::ProtocolContext,
        modulus_conversion::convert_shares::convert_shares_for_a_bit,
        sort::bit_permutation::BitPermutation,
        sort::SortStep::{ApplyInv, BitPermutationStep, ComposeStep},
        IpaProtocolStep::Sort,
    },
    secret_sharing::Replicated,
};

use super::{compose::Compose, secureapplyinv::SecureApplyInv};
use embed_doc_image::embed_doc_image;

/// This is an implementation of `GenPerm` (Algorithm 6) described in:
/// "An Efficient Secure Three-Party Sorting Protocol with an Honest Majority"
/// by K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, N. Kiribuchi, and B. Pinkas
/// <https://eprint.iacr.org/2019/695.pdf>.
#[derive(Debug)]
pub struct GenerateSortPermutation<'a> {
    input: &'a [u64],
    num_bits: u8,
}

impl<'a> GenerateSortPermutation<'a> {
    #[allow(dead_code)]
    pub fn new(input: &'a [u64], num_bits: u8) -> GenerateSortPermutation {
        Self { input, num_bits }
    }

    #[allow(dead_code)]
    #[embed_doc_image("semi_honest_sort", "images/sort/semi-honest-sort.png")]
    /// This protocol generates permutation of a stable sort for the given shares of inputs.
    /// ![Generate sort permutation steps][semi_honest_sort]
    /// Steps
    /// For each bit of input share, following steps are executed
    /// 1. For the current bit, get replicated shares in Field using modulus conversion
    /// 2. 1st bit onwards, sort ith bit based on i-1th bits by applying i-1th composition on ith bit
    /// 3  Sort ith bit by computing bit permutation
    /// 4. 1st bit onwards, compute ith composition by composing i-1th composition on ith permutation
    /// In the end, n-1th composition is returned. This is the permutation which sorts the inputs
    pub async fn execute<F: Field>(
        &self,
        ctx: ProtocolContext<'_, Replicated<F>, F>,
    ) -> Result<Vec<Replicated<F>>, BoxError> {
        let mut i_minus_1_compose = Vec::with_capacity(self.input.len());
        for bit_num in 0..self.num_bits {
            let ctx = ctx.narrow(&Sort(bit_num));
            let mut bit_value_share =
                convert_shares_for_a_bit(&ctx, self.input, self.num_bits, bit_num).await?;
            if bit_num != 0 {
                SecureApplyInv::execute(
                    &ctx.narrow(&ApplyInv),
                    &mut bit_value_share,
                    &mut i_minus_1_compose.clone(),
                )
                .await?;
            }
            let mut bit_i_permutation = BitPermutation::new(&bit_value_share)
                .execute(ctx.narrow(&BitPermutationStep))
                .await?;

            if bit_num != 0 {
                Compose::new(&mut i_minus_1_compose, &mut bit_i_permutation)
                    .execute(ctx.narrow(&ComposeStep))
                    .await?;
            }
            i_minus_1_compose = bit_i_permutation;
        }
        Ok(i_minus_1_compose)
    }
}

#[cfg(test)]
mod tests {
    use futures::future::try_join_all;
    use rand::Rng;

    use crate::{
        protocol::{sort::{generate_sort_permutation::GenerateSortPermutation}, QueryId},
        test_fixture::{make_contexts, make_world, validate_list_of_shares, logging}, ff::Fp31, error::BoxError,
    };

    #[tokio::test]
    pub async fn generate_sort_permutation() -> Result<(), BoxError> {
        logging::setup();
        let world = make_world(QueryId);
        let [ctx0, ctx1, ctx2] = make_contexts::<Fp31>(&world);
        let num_bits = 64;
        let mut rng = rand::thread_rng();

        let batchsize = 30;

        let mut match_keys: Vec<u64> = Vec::new();
        for _ in 0..batchsize {
            match_keys.push(rng.gen::<u64>());
        }

        let mut expected_sort_output: Vec<u128> = (0..batchsize).collect();

        let mut permutation = permutation::sort(match_keys.clone());
        permutation.apply_inv_slice_in_place(&mut expected_sort_output);

        let input_len = match_keys.len();
        let mut shares = [
            Vec::with_capacity(input_len),
            Vec::with_capacity(input_len),
            Vec::with_capacity(input_len),
        ];
        for match_key in match_keys {
            let share_0 = rng.gen::<u64>();
            let share_1 = rng.gen::<u64>();
            let share_2 = match_key ^ share_0 ^ share_1;

            shares[0].push(share_0);
            shares[1].push(share_1);
            shares[2].push(share_2);
        }

        let mut result = try_join_all(vec![
            GenerateSortPermutation::new(&shares[0], num_bits).execute(ctx0),
            GenerateSortPermutation::new(&shares[1], num_bits).execute(ctx1),
            GenerateSortPermutation::new(&shares[2], num_bits).execute(ctx2),
        ])
        .await?;

        assert_eq!(result[0].len(), input_len);
        assert_eq!(result[1].len(), input_len);
        assert_eq!(result[2].len(), input_len);

        validate_list_of_shares(
            &expected_sort_output,
            &(result.remove(0), result.remove(0), result.remove(0)),
        );
        Ok(())
    }
}
