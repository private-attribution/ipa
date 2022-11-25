use crate::protocol::context::SemiHonestContext;
use crate::{
    error::Error,
    ff::Field,
    protocol::{context::Context, sort::ApplyInvStep::ShuffleInputs},
    secret_sharing::Replicated,
};
use embed_doc_image::embed_doc_image;

use super::{apply::apply_inv, shuffle::shuffle_shares};

/// This is an implementation of ApplyInv (Algorithm 4) found in the paper:
/// "An Efficient Secure Three-Party Sorting Protocol with an Honest Majority"
/// by K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, N. Kiribuchi, and B. Pinkas
/// <https://eprint.iacr.org/2019/695.pdf>
/// This is a protocol that applies the inverse of a secret-shared permutation to a vector of secret-shared values
/// Input: Each helpers know their own secret shares of input and permutation
/// Output: At the end of the protocol, all helpers receive inputs after the permutation is applied
#[embed_doc_image("secureapplyinv", "images/sort/secureapplyinv.png")]
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
pub async fn secureapplyinv<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    input: Vec<Replicated<F>>,
    random_permutations_for_shuffle: &(Vec<u32>, Vec<u32>),
    shuffled_sort_permutation: &[u32],
) -> Result<Vec<Replicated<F>>, Error> {
    let mut shuffled_input = shuffle_shares(
        input,
        random_permutations_for_shuffle,
        ctx.narrow(&ShuffleInputs),
    )
    .await?;

    apply_inv(shuffled_sort_permutation, &mut shuffled_input);
    Ok(shuffled_input)
}

#[cfg(test)]
mod tests {
    use futures::future::try_join_all;
    use proptest::prelude::Rng;
    use rand::seq::SliceRandom;

    use crate::protocol::context::Context;
    use crate::{
        ff::Fp31,
        protocol::{
            sort::{apply::apply_inv, generate_sort_permutation::shuffle_and_reveal_permutation},
            QueryId,
        },
        test_fixture::{generate_shares, make_contexts, make_world, validate_list_of_shares},
    };

    use super::secureapplyinv;

    #[tokio::test]
    pub async fn test_secureapplyinv() {
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

            let [input0, input1, input2] = generate_shares::<Fp31>(&input);

            let world = make_world(QueryId);
            let [ctx0, ctx1, ctx2] = make_contexts(&world);
            let permutation: Vec<u128> = permutation.iter().map(|x| u128::from(*x)).collect();

            let [perm0, perm1, perm2] = generate_shares::<Fp31>(&permutation);

            let perm_and_randoms: [_; 3] = try_join_all([
                shuffle_and_reveal_permutation(ctx0.narrow("shuffle_reveal"), BATCHSIZE, perm0),
                shuffle_and_reveal_permutation(ctx1.narrow("shuffle_reveal"), BATCHSIZE, perm1),
                shuffle_and_reveal_permutation(ctx2.narrow("shuffle_reveal"), BATCHSIZE, perm2),
            ])
            .await
            .unwrap()
            .try_into()
            .unwrap();

            let h0_future =
                secureapplyinv(ctx0, input0, &perm_and_randoms[0].1, &perm_and_randoms[0].0);
            let h1_future =
                secureapplyinv(ctx1, input1, &perm_and_randoms[1].1, &perm_and_randoms[1].0);
            let h2_future =
                secureapplyinv(ctx2, input2, &perm_and_randoms[2].1, &perm_and_randoms[2].0);

            let result: [_; 3] = try_join_all([h0_future, h1_future, h2_future])
                .await
                .unwrap()
                .try_into()
                .unwrap();

            // We should get the same result of applying inverse as what we get when applying in clear
            validate_list_of_shares(&expected_result, &result);
        }
    }
}
