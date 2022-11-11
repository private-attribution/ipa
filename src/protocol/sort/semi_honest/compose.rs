use crate::{
    error::BoxError,
    ff::Field,
    protocol::{context::ProtocolContext, reveal::reveal_permutation, sort::apply::apply_inv},
    secret_sharing::Replicated,
};
use embed_doc_image::embed_doc_image;

use super::{
    shuffle::{get_two_of_three_random_permutations, Shuffle},
    ComposeStep::{RevealPermutation, ShuffleSigma, UnshuffleRho},
};

/// This is an implementation of Compose (Algorithm 5) found in the paper:
/// "An Efficient Secure Three-Party Sorting Protocol with an Honest Majority"
/// by K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, N. Kiribuchi, and B. Pinkas
/// <https://eprint.iacr.org/2019/695.pdf>
/// This protocol composes two permutations by applying one secret-shared permutation(sigma) to another secret-shared permutation(rho)
/// Input: First permutation(sigma) i.e. permutation that sorts all i-1th bits and other permutation(rho) i.e. sort permutation for ith bit
/// Output: All helpers receive secret shares of permutation which sort inputs until ith bits.
#[derive(Debug)]
pub struct Compose {}

impl Compose {
    #[embed_doc_image("compose", "images/sort/compose.png")]
    /// This algorithm composes two permutations (`rho` and `sigma`). Both permutations are secret-shared,
    /// and none of the helpers should learn it through this protocol.
    /// Steps
    /// ![Compose steps][compose]
    /// 1. Generate random permutations using prss
    /// 2. First permutation (sigma) is shuffled with random permutations
    /// 3. Reveal the permutation
    /// 4. Revealed permutation is applied locally on another permutation shares (rho)
    /// 5. Unshuffle the permutation with the same random permutations used in step 2, to undo the effect of the shuffling
    #[allow(dead_code)]
    pub async fn execute<F: Field>(
        ctx: ProtocolContext<'_, Replicated<F>, F>,
        sigma: Vec<Replicated<F>>,
        rho: Vec<Replicated<F>>,
    ) -> Result<Vec<Replicated<F>>, BoxError> {
        let random_permutations = get_two_of_three_random_permutations(rho.len(), &ctx.prss());

        let shuffled_sigma = Shuffle::new(sigma, random_permutations.clone())
            .execute(ctx.narrow(&ShuffleSigma))
            .await?;

        let revealed_permutation =
            reveal_permutation(ctx.narrow(&RevealPermutation), &shuffled_sigma).await?;
        let mut applied_rho = rho;
        apply_inv(revealed_permutation, &mut applied_rho);

        let unshuffled_rho = Shuffle::new(applied_rho, random_permutations)
            .execute_unshuffle(ctx.narrow(&UnshuffleRho))
            .await?;

        Ok(unshuffled_rho)
    }
}

#[cfg(test)]
mod tests {
    use super::Compose;
    use crate::{
        error::BoxError,
        ff::Fp31,
        protocol::{sort::apply::apply_inv, QueryId},
        test_fixture::{
            generate_shares, make_contexts, make_world, validate_list_of_shares, TestWorld,
        },
    };
    use permutation::Permutation;
    use rand::seq::SliceRandom;
    use tokio::try_join;

    #[tokio::test]
    pub async fn compose() -> Result<(), BoxError> {
        const BATCHSIZE: usize = 25;
        for _ in 0..10 {
            let mut rng_sigma = rand::thread_rng();
            let mut rng_rho = rand::thread_rng();

            let mut sigma: Vec<usize> = (0..BATCHSIZE).collect();
            sigma.shuffle(&mut rng_sigma);

            let sigma_u128: Vec<u128> = sigma.iter().map(|x| *x as u128).collect();

            let mut rho: Vec<usize> = (0..BATCHSIZE).collect();
            rho.shuffle(&mut rng_rho);
            let rho_u128: Vec<u128> = rho.iter().map(|x| *x as u128).collect();

            let mut rho_composed = rho_u128.clone();
            apply_inv(Permutation::oneline(sigma.clone()), &mut rho_composed);

            let sigma_shares = generate_shares::<Fp31>(sigma_u128);
            let mut rho_shares = generate_shares::<Fp31>(rho_u128);
            let world: TestWorld = make_world(QueryId);
            let [ctx0, ctx1, ctx2] = make_contexts(&world);

            let h0_future = Compose::execute(ctx0, sigma_shares.0, rho_shares.0);
            let h1_future = Compose::execute(ctx1, sigma_shares.1, rho_shares.1);
            let h2_future = Compose::execute(ctx2, sigma_shares.2, rho_shares.2);

            rho_shares = try_join!(h0_future, h1_future, h2_future)?;

            assert_eq!(rho_shares.0.len(), BATCHSIZE);
            assert_eq!(rho_shares.1.len(), BATCHSIZE);
            assert_eq!(rho_shares.2.len(), BATCHSIZE);

            // We should get the same result of applying inverse of sigma on rho as in clear
            validate_list_of_shares(&rho_composed, &rho_shares);
        }
        Ok(())
    }
}
