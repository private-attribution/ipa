use crate::{
    error::BoxError,
    ff::Field,
    protocol::{context::ProtocolContext, reveal::reveal_a_permutation},
    secret_sharing::Replicated,
};
use embed_doc_image::embed_doc_image;

use super::{
    apply::apply_inv,
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
pub struct Compose<'a, F> {
    sigma: &'a mut Vec<Replicated<F>>,
    rho: &'a mut Vec<Replicated<F>>,
}

impl<'a, F: Field> Compose<'a, F> {
    #[allow(dead_code)]
    pub fn new(sigma: &'a mut Vec<Replicated<F>>, rho: &'a mut Vec<Replicated<F>>) -> Self {
        Self { sigma, rho }
    }
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
    pub async fn execute(&mut self, ctx: ProtocolContext<'_, Replicated<F>, F>) -> Result<(), BoxError> {
        let mut random_permutations =
            get_two_of_three_random_permutations(self.rho.len(), &ctx.prss());
        let mut random_permutations_copy = random_permutations.clone();

        Shuffle::new(self.sigma)
            .execute(ctx.narrow(&ShuffleSigma), &mut random_permutations)
            .await?;

        let mut perms = reveal_a_permutation(ctx.narrow(&RevealPermutation), self.sigma).await?;

        apply_inv(&mut perms, &mut self.rho);

        Shuffle::new(self.rho)
            .execute_unshuffle(ctx.narrow(&UnshuffleRho), &mut random_permutations_copy)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use permutation::Permutation;
    use rand::seq::SliceRandom;
    use tokio::try_join;

    use crate::{
        error::BoxError,
        protocol::{
            sort::{apply::apply_inv, compose::Compose},
            QueryId,
        },
        test_fixture::{
            generate_shares, make_contexts, make_world, validate_list_of_shares, TestWorld,
        },
    };

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
            apply_inv(&mut Permutation::oneline(sigma.clone()), &mut rho_composed);

            let mut sigma_shares = generate_shares(sigma_u128);
            let mut rho_shares = generate_shares(rho_u128);
            let world: TestWorld = make_world(QueryId);
            let [ctx0, ctx1, ctx2] = make_contexts(&world);

            let mut compose0 = Compose::new(&mut sigma_shares.0, &mut rho_shares.0);
            let mut compose1 = Compose::new(&mut sigma_shares.1, &mut rho_shares.1);
            let mut compose2 = Compose::new(&mut sigma_shares.2, &mut rho_shares.2);

            let h0_future = compose0.execute(ctx0);
            let h1_future = compose1.execute(ctx1);
            let h2_future = compose2.execute(ctx2);

            try_join!(h0_future, h1_future, h2_future)?;

            assert_eq!(rho_shares.0.len(), BATCHSIZE);
            assert_eq!(rho_shares.1.len(), BATCHSIZE);
            assert_eq!(rho_shares.2.len(), BATCHSIZE);

            // We should get the same result of applying inverse of sigma on rho as in clear
            validate_list_of_shares(&rho_composed, &rho_shares);
        }
        Ok(())
    }
}
