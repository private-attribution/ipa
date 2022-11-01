use crate::{
    error::BoxError,
    ff::Field,
    protocol::{
        context::ProtocolContext,
        modulus_conversion::convert_shares::convert_all_shares,
        sort::bit_permutations::BitPermutations,
        sort::SortStep::{ApplyInv, BitPermutation, ComposeStep},
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
pub struct GenerateSortPermutations<'a> {
    input: &'a [u64],
}

impl<'a> GenerateSortPermutations<'a> {
    #[allow(dead_code)]
    pub fn new(input: &'a [u64]) -> GenerateSortPermutations {
        Self { input }
    }

    #[allow(dead_code)]
    #[embed_doc_image("semi_honest_sort", "images/sort/semi-honest-sort.png")]
    /// This protocol generates permutation of a stable sort for the given inputs.
    /// ![Generate sort permutations steps][semi_honest_sort]
    /// Steps
    /// 1. Obtain bit-wise shares in Field by calling modulus conversion on the input match keys.
    /// 2. Obtain bit permutation to sort 0th input bit. This is also 0th bit composition (i.e. sigma)
    /// 3. For 1st until n bits, following steps are repeated
    /// 3i.  Apply inverse of i-1th bit permutation on ith input bits
    /// 3ii. Obtain bit permutation to sort ith input bit
    /// 3iii.Compose ith bit permutation on i-1th composition. We have now obtained ith composition
    /// 4. Return nth composition as the permutation to sort the given inputs
    pub async fn execute<F: Field>(
        &self,
        ctx: ProtocolContext<'_, Replicated<F>, F>,
    ) -> Result<Vec<Replicated<F>>, BoxError> {
        let mut bits = convert_all_shares(&ctx, self.input).await?;
        let mut sigma = BitPermutations::new(&bits[0])
            .execute(ctx.narrow(&BitPermutation(0)))
            .await?;
        for (i, ith_bit) in bits.iter_mut().enumerate().skip(1) {
            SecureApplyInv::execute(
                &ctx.narrow(&ApplyInv(i.try_into().unwrap())),
                ith_bit,
                &mut sigma.clone(),
            )
            .await?;
            let mut rho = BitPermutations::new(ith_bit)
                .execute(ctx.narrow(&BitPermutation(i.try_into().unwrap())))
                .await?;
            Compose::new(&mut sigma, &mut rho)
                .execute(ctx.narrow(&ComposeStep(i.try_into().unwrap())))
                .await?;
            sigma = rho;
        }
        Ok(sigma)
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use tokio::try_join;

    use crate::{
        protocol::{sort::generate_sort_permutations::GenerateSortPermutations, QueryId},
        test_fixture::{make_contexts, make_world, validate_list_of_shares}, ff::Fp31,
    };

    #[tokio::test]
    pub async fn generate_sort_permutations() {
        let world = make_world(QueryId);
        let [ctx0, ctx1, ctx2] = make_contexts::<Fp31>(&world);
        let mut rng = rand::thread_rng();
        let mask = (1_u64 << 63) - 1;

        let batchsize = 30;

        let mut match_keys: Vec<u64> = Vec::new();
        for _ in 0..batchsize {
            match_keys.push(rng.gen::<u64>() & mask);
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
            let share_0 = rng.gen::<u64>() & mask;
            let share_1 = rng.gen::<u64>() & mask;
            let share_2 = match_key ^ share_0 ^ share_1;

            shares[0].push(share_0);
            shares[1].push(share_1);
            shares[2].push(share_2);
        }

        let sortperms0 = GenerateSortPermutations::new(&shares[0]);
        let sortperms1 = GenerateSortPermutations::new(&shares[1]);
        let sortperms2 = GenerateSortPermutations::new(&shares[2]);

        let h0_future = sortperms0.execute(ctx0);
        let h1_future = sortperms1.execute(ctx1);
        let h2_future = sortperms2.execute(ctx2);

        let result = try_join!(h0_future, h1_future, h2_future).unwrap();

        assert_eq!(result.0.len(), input_len);
        assert_eq!(result.1.len(), input_len);
        assert_eq!(result.2.len(), input_len);

        validate_list_of_shares(&expected_sort_output, &result);
    }
}
