use crate::{
    error::BoxError,
    ff::Field,
    protocol::{
        context::ProtocolContext,
        reveal::reveal_permutation,
        sort::ApplyInvStep::{RevealPermutation, ShuffleInputs, ShufflePermutation},
    },
    secret_sharing::Replicated,
};
use embed_doc_image::embed_doc_image;

use super::{
    apply::apply_inv,
    shuffle::{get_two_of_three_random_permutations, shuffle_shares},
};
use futures::future::try_join;

/// This is an implementation of ApplyInv (Algorithm 4) found in the paper:
/// "An Efficient Secure Three-Party Sorting Protocol with an Honest Majority"
/// by K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, N. Kiribuchi, and B. Pinkas
/// <https://eprint.iacr.org/2019/695.pdf>
/// This is a protocol that applies the inverse of a secret-shared permutation to a vector of secret-shared values
/// Input: Each helpers know their own secret shares of input and permutation
/// Output: At the end of the protocol, all helpers receive inputs after the permutation is applied
#[derive(Debug)]
#[embed_doc_image("secureapplyinv", "images/sort/secureapplyinv.png")]
pub struct SecureApplyInv {}

impl SecureApplyInv {
    /// This algorithm applies a permutation to the `input` vector. The permutation is secret-shared,
    /// and none of the helpers should learn it through this protocol.
    /// To keep the permutation secret, it (and the inputs) are first randomly securely shuffled.
    /// After this shuffle, the permutation can be revealed.
    /// An adversary can only obtain a shuffled permutation, which is just a random permutation.
    /// Steps
    /// ![Secure Apply Inv steps][secureapplyinv]
    /// 1. Generate random permutations using prss
    /// 2. Secret shared permutation is shuffled with random permutations
    /// 3. Secret shared value is shuffled using the same random permutations
    /// 4. The permutation is revealed
    /// 5. All helpers call `apply` to apply the permutation locally.
    pub async fn execute<F: Field>(
        ctx: ProtocolContext<'_, Replicated<F>, F>,
        input: Vec<Replicated<F>>,
        sort_permutation: Vec<Replicated<F>>,
    ) -> Result<Vec<Replicated<F>>, BoxError> {
        let (left_random_permutation, right_random_permutation) =
            get_two_of_three_random_permutations(input.len(), &ctx.prss());

        let (mut shuffled_input, shuffled_sort_permutation) = try_join(
            shuffle_shares(
                input,
                &left_random_permutation,
                &right_random_permutation,
                ctx.narrow(&ShuffleInputs),
            ),
            shuffle_shares(
                sort_permutation,
                &left_random_permutation,
                &right_random_permutation,
                ctx.narrow(&ShufflePermutation),
            ),
        )
        .await?;
        let revealed_permutation =
            reveal_permutation(ctx.narrow(&RevealPermutation), &shuffled_sort_permutation).await?;

        apply_inv(&revealed_permutation, &mut shuffled_input);
        Ok(shuffled_input)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::Rng;
    use rand::seq::SliceRandom;
    use tokio::try_join;

    use crate::{
        ff::Fp31,
        protocol::{sort::apply::apply_inv, QueryId},
        test_fixture::{generate_shares, make_contexts, make_world, validate_list_of_shares},
    };

    use super::SecureApplyInv;

    #[tokio::test]
    pub async fn secureapplyinv() {
        const BATCHSIZE: u32 = 25;
        for _ in 0..10 {
            let mut rng = rand::thread_rng();
            let mut input: Vec<u128> = Vec::with_capacity(BATCHSIZE as usize);
            for _ in 0..BATCHSIZE {
                input.push(rng.gen::<u128>() % 31_u128);
            }

            let mut permutation: Vec<u32> = (0..BATCHSIZE).collect();
            permutation.shuffle(&mut rng);

            let mut expected_result = input.clone();

            // Applying permutation on the input in clear to get the expected result
            apply_inv(&permutation, &mut expected_result);

            let permutation: Vec<u128> = permutation.iter().map(|x| u128::from(*x)).collect();

            let perm_shares = generate_shares::<Fp31>(permutation);
            let mut input_shares = generate_shares::<Fp31>(input);

            let world = make_world(QueryId);
            let [ctx0, ctx1, ctx2] = make_contexts(&world);

            let h0_future = SecureApplyInv::execute(ctx0, input_shares.0, perm_shares.0);
            let h1_future = SecureApplyInv::execute(ctx1, input_shares.1, perm_shares.1);
            let h2_future = SecureApplyInv::execute(ctx2, input_shares.2, perm_shares.2);

            input_shares = try_join!(h0_future, h1_future, h2_future).unwrap();

            assert_eq!(input_shares.0.len(), BATCHSIZE as usize);
            assert_eq!(input_shares.1.len(), BATCHSIZE as usize);
            assert_eq!(input_shares.2.len(), BATCHSIZE as usize);

            // We should get the same result of applying inverse as what we get when applying in clear
            validate_list_of_shares(&expected_result, &input_shares);
        }
    }
}
