use crate::{
    error::BoxError,
    protocol::{
        context::ProtocolContext,
        reveal::reveal_a_permutation,
        sort::ApplyInvStep::{RevealPermutation, ShuffleInputs, ShufflePermutation},
    },
    secret_sharing::Replicated, ff::Field,
};
use embed_doc_image::embed_doc_image;

use super::{
    apply::apply,
    shuffle::{generate_random_permutations_using_prss, Shuffle},
};
use tokio::try_join;

/// This is an implementation of ApplyInv (Algorithm 4) found in the paper:
/// "An Efficient Secure Three-Party Sorting Protocol with an Honest Majority"
/// by K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, N. Kiribuchi, and B. Pinkas
/// https://eprint.iacr.org/2019/695.pdf
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
    #[allow(dead_code)]
    pub async fn execute<F: Field>(
        ctx: &ProtocolContext<'_, F>,
        input: &'_ mut Vec<Replicated<F>>,
        sort_permutation: &'_ mut Vec<Replicated<F>>,
    ) -> Result<(), BoxError> {
        let mut random_permutations =
            generate_random_permutations_using_prss(input.len(), &ctx.prss());
        let mut random_permutations_copy = random_permutations.clone();

        let mut shuffle_inputs = Shuffle::new(input);
        let mut shuffle_permutation = Shuffle::new(sort_permutation);

        let (_, _) = try_join!(
            shuffle_inputs.execute(ctx.narrow(&ShuffleInputs), &mut random_permutations,),
            shuffle_permutation.execute(
                ctx.narrow(&ShufflePermutation),
                &mut random_permutations_copy
            ),
        )?;
        let mut permutation =
            reveal_a_permutation(&ctx.narrow(&RevealPermutation), sort_permutation).await?;

        // 5. apply the permutation on the shuffled input
        // The paper suggests taking apply_inv. However, Permutation::oneline returns an inverted permutation, so we are negating
        // the effect by just calling apply instead of apply_inv here
        apply(&mut permutation, input);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use permutation::Permutation;
    use rand::seq::SliceRandom;
    use tokio::try_join;

    use crate::{
        protocol::{sort::apply::apply_inv, QueryId},
        test_fixture::{generate_shares, make_contexts, make_world, validate_result_from_shares},
    };

    use super::SecureApplyInv;

    #[tokio::test]
    pub async fn secureapplyinv() {
        const BATCHSIZE: usize = 25;
        for _ in 0..10 {
            let mut rng = rand::thread_rng();
            let input: Vec<u128> = (0..(BATCHSIZE as u128)).collect();

            let mut permutation: Vec<usize> = (0..BATCHSIZE).collect();
            permutation.shuffle(&mut rng);

            let mut expected_result = input.clone();
            let mut cloned_perm = Permutation::oneline(permutation.clone()).inverse();

            apply_inv(&mut cloned_perm, &mut expected_result);

            let permutation: Vec<u128> = permutation.iter().map(|x| *x as u128).collect();

            let mut perm_shares = generate_shares(permutation);
            let mut input_shares = generate_shares(input);

            let world = make_world(QueryId);
            let context = make_contexts(&world);

            let h0_future =
                SecureApplyInv::execute(&context[0], &mut input_shares.0, &mut perm_shares.0);
            let h1_future =
                SecureApplyInv::execute(&context[1], &mut input_shares.1, &mut perm_shares.1);
            let h2_future =
                SecureApplyInv::execute(&context[2], &mut input_shares.2, &mut perm_shares.2);

            try_join!(h0_future, h1_future, h2_future).unwrap();

            assert_eq!(input_shares.0.len(), BATCHSIZE);
            assert_eq!(input_shares.1.len(), BATCHSIZE);
            assert_eq!(input_shares.2.len(), BATCHSIZE);

            // We should get the same result of applying inverse as what we get when applying in clear
            validate_result_from_shares(&expected_result, &input_shares);
        }
    }
}
