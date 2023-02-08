use crate::secret_sharing::SecretSharing;
use crate::{error::Error, ff::Field, protocol::context::Context};
use embed_doc_image::embed_doc_image;

use super::{apply::apply, shuffle::unshuffle_shares, ComposeStep::UnshuffleRho};

#[embed_doc_image("compose", "images/sort/compose.png")]
/// This is an implementation of Compose (Algorithm 5) found in the paper:
/// "An Efficient Secure Three-Party Sorting Protocol with an Honest Majority"
/// by K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, N. Kiribuchi, and B. Pinkas
/// <https://eprint.iacr.org/2019/695.pdf>
///
/// This protocol composes two permutations by applying one secret-shared permutation(sigma) to another secret-shared permutation(rho)
/// Input: First permutation(sigma) i.e. permutation that sorts all i-1th bits and other permutation(rho) i.e. sort permutation for ith bit
/// Output: All helpers receive secret shares of permutation which sort inputs until ith bits.
///
/// This algorithm composes two permutations (`rho` and `sigma`). Both permutations are secret-shared,
/// and none of the helpers should learn it through this protocol.
///
/// Steps
///
/// 1. Generate random permutations using prss
/// 2. First permutation (sigma) is shuffled with random permutations
/// 3. Reveal the permutation
/// 4. Revealed permutation is applied locally on another permutation shares (rho)
/// 5. Unshuffle the permutation with the same random permutations used in step 2, to undo the effect of the shuffling
///
/// ![Compose steps][compose]
pub async fn compose<F: Field, S: SecretSharing<F>, C: Context<F, Share = S>>(
    ctx: C,
    random_permutations_for_shuffle: (&[u32], &[u32]),
    shuffled_sigma: &[u32],
    mut rho: Vec<S>,
) -> Result<Vec<S>, Error> {
    apply(shuffled_sigma, &mut rho);

    let unshuffled_rho = unshuffle_shares(
        rho,
        random_permutations_for_shuffle,
        ctx.narrow(&UnshuffleRho),
    )
    .await?;

    Ok(unshuffled_rho)
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use crate::protocol::context::Context;
    use crate::rand::thread_rng;
    use crate::test_fixture::{Reconstruct, Runner};
    use crate::{
        ff::Fp31,
        protocol::sort::{
            apply::apply, compose::compose, generate_permutation::shuffle_and_reveal_permutation,
        },
        test_fixture::TestWorld,
    };
    use rand::seq::SliceRandom;

    #[tokio::test]
    pub async fn semi_honest() {
        const BATCHSIZE: u32 = 25;
        let world = TestWorld::new().await;
        let mut rng_sigma = thread_rng();
        let mut rng_rho = thread_rng();

        let mut sigma: Vec<u32> = (0..BATCHSIZE).collect();
        sigma.shuffle(&mut rng_sigma);

        let mut rho: Vec<u128> = (0..BATCHSIZE.try_into().unwrap()).collect();
        rho.shuffle(&mut rng_rho);

        let mut expected_result = rho.clone();
        apply(&sigma, &mut expected_result);

        let result = world
            .semi_honest(
                (
                    sigma.into_iter().map(u128::from).map(Fp31::from),
                    rho.into_iter().map(Fp31::from),
                ),
                |ctx, (m_sigma_shares, m_rho_shares)| async move {
                    let sigma_and_randoms = shuffle_and_reveal_permutation(
                        ctx.narrow("shuffle_reveal"),
                        m_sigma_shares,
                    )
                    .await
                    .unwrap();

                    compose(
                        ctx,
                        (
                            sigma_and_randoms.randoms_for_shuffle.0.as_slice(),
                            sigma_and_randoms.randoms_for_shuffle.1.as_slice(),
                        ),
                        &sigma_and_randoms.revealed,
                        m_rho_shares,
                    )
                    .await
                    .unwrap()
                },
            )
            .await;

        assert_eq!(&expected_result[..], &result.reconstruct());
    }
}
