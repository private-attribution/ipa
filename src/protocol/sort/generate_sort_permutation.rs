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
#[derive(Debug)]
pub struct GenerateSortPermutation<'a> {
    input: &'a [(u64, u64)],
    num_bits: u8,
}

impl<'a> GenerateSortPermutation<'a> {
    #[must_use]
    pub fn new(input: &'a [(u64, u64)], num_bits: u8) -> GenerateSortPermutation {
        Self { input, num_bits }
    }

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
    pub async fn execute<F: Field>(
        &self,
        ctx: ProtocolContext<'_, Replicated<F>, F>,
    ) -> Result<Vec<Replicated<F>>, BoxError> {
        let ctx_0 = ctx.narrow(&Sort(0));
        let bit_0 = convert_shares_for_a_bit(
            ctx_0.narrow(&ModulusConversion),
            self.input,
            self.num_bits,
            0,
        )
        .await?;
        let bit_0_permutation = bit_permutation(ctx_0.narrow(&BitPermutationStep), &bit_0).await?;

        let mut composed_less_significant_bits_permutation = bit_0_permutation;
        for bit_num in 1..self.num_bits {
            let ctx_bit = ctx.narrow(&Sort(bit_num));
            let bit_i = convert_shares_for_a_bit(
                ctx_bit.narrow(&ModulusConversion),
                self.input,
                self.num_bits,
                bit_num,
            )
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
            ).await?;
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
}

#[cfg(test)]
mod tests {
    use std::iter::zip;

    use futures::future::try_join_all;
    use rand::Rng;

    use crate::{
        error::BoxError,
        ff::{Field, Fp32BitPrime},
        protocol::{sort::generate_sort_permutation::GenerateSortPermutation, QueryId},
        test_fixture::{logging, make_contexts, make_world, validate_and_reconstruct},
    };

    #[tokio::test]
    pub async fn generate_sort_permutation() -> Result<(), BoxError> {
        const ROUNDS: usize = 50;
        const NUM_BITS: u8 = 24;
        const MASK: u64 = u64::MAX >> (64 - NUM_BITS);

        logging::setup();
        let world = make_world(QueryId);
        let [ctx0, ctx1, ctx2] = make_contexts::<Fp32BitPrime>(&world);
        let mut rng = rand::thread_rng();

        let mut match_keys: Vec<u64> = Vec::new();
        for _ in 0..ROUNDS {
            match_keys.push(rng.gen::<u64>() & MASK);
        }

        let mut shares = [
            Vec::with_capacity(ROUNDS),
            Vec::with_capacity(ROUNDS),
            Vec::with_capacity(ROUNDS),
        ];
        for match_key in match_keys.clone() {
            let share_0 = rng.gen::<u64>() & MASK;
            let share_1 = rng.gen::<u64>() & MASK;
            let share_2 = match_key ^ share_0 ^ share_1;

            shares[0].push((share_0, share_1));
            shares[1].push((share_1, share_2));
            shares[2].push((share_2, share_0));
        }

        let [result0, result1, result2] = <[_; 3]>::try_from(
            try_join_all([
                GenerateSortPermutation::new(&shares[0], NUM_BITS).execute(ctx0),
                GenerateSortPermutation::new(&shares[1], NUM_BITS).execute(ctx1),
                GenerateSortPermutation::new(&shares[2], NUM_BITS).execute(ctx2),
            ])
            .await?,
        )
        .unwrap();

        assert_eq!(result0.len(), ROUNDS);
        assert_eq!(result1.len(), ROUNDS);
        assert_eq!(result2.len(), ROUNDS);

        let mut mpc_sorted_list: Vec<u128> = (0..ROUNDS).map(|i| i as u128).collect();
        for (match_key, (r0, (r1, r2))) in
            zip(match_keys.iter(), zip(result0, zip(result1, result2)))
        {
            let index = validate_and_reconstruct(&r0, &r1, &r2);
            mpc_sorted_list[index.as_u128() as usize] = u128::from(*match_key);
        }

        let mut sorted_match_keys = match_keys.clone();
        sorted_match_keys.sort_unstable();
        for i in 0..ROUNDS {
            assert_eq!(u128::from(sorted_match_keys[i]), mpc_sorted_list[i]);
        }

        Ok(())
    }
}
