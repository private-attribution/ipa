use crate::{
    error::BoxError,
    field::Field,
    helpers::{fabric::Network, prss::SpaceIndex},
    protocol::{context::ProtocolContext, RecordId, Step},
    secret_sharing::Replicated,
};
use embed_doc_image::embed_doc_image;
use futures::future::try_join_all;
use permutation::Permutation;

use super::{
    apply::apply_inv,
    compose_ipa_step, concat_two_ipa_steps,
    shuffle::{generate_random_permutation, Shuffle},
    ComposeStep::{
        self, GenerateRandomPermutation, ShuffleLastPermutation, UnshuffleNewPermutation,
    },
};
/// This is COMPOSE(Algorithm 5) described in <https://eprint.iacr.org/2019/695.pdf>.
/// This is a protocol that applies a new permutation(rho) to the last permutation(sigma)
/// Input: Last permutation i.e. i-1th bits sort permutation and new permutation i.e. ith bit sort permutation
/// Output: At the end of the protocol, all helpers receive composed permutation which can be applied to i+1th bit to sort according to upto i bits
#[derive(Debug)]
pub struct Compose<'a, F> {
    last_permutation: &'a mut Vec<Replicated<F>>,
    new_permutation: &'a mut Vec<Replicated<F>>,
}

impl<'a, F: Field> Compose<'a, F> {
    #[allow(dead_code)]
    pub fn new(
        last_permutation: &'a mut Vec<Replicated<F>>,
        new_permutation: &'a mut Vec<Replicated<F>>,
    ) -> Self {
        Self {
            last_permutation,
            new_permutation,
        }
    }
    #[embed_doc_image("compose", "images/sort/compose.png")]
    /// In a nutshell, this algorithm applies a permutation on the inputs. The permutation is not available in clear and
    /// we do not want to reveal the actual permutation to any of the helpers while applying it.
    /// Steps
    /// ![Compose steps][compose]
    /// 1. Generate a permutation
    /// 2. Last permutation (sigma) is shuffled
    /// 3. Reveal the permutation
    /// 4. New permutation (rho) is applied locally by helpers
    /// 5. Unshuffle the permutation
    #[allow(dead_code)]
    pub async fn execute<N: Network<S>, S: Step + SpaceIndex>(
        &mut self,
        ctx: &ProtocolContext<'_, S, N>,
        step: fn(ComposeStep) -> S,
    ) -> Result<(), BoxError> {
        // 1. Generate permutation
        let permutations = generate_random_permutation(
            self.new_permutation.len(),
            &ctx.participant[step(GenerateRandomPermutation)],
        );

        // 2. Shuffle permutations
        let shuffle_last_perm_fn = compose_ipa_step!(ShuffleLastPermutation, step);
        let mut shuffle_permutation = Shuffle::new(self.last_permutation, shuffle_last_perm_fn);
        let h0_future = shuffle_permutation.execute_shuffle(ctx, &permutations);
        h0_future.await.unwrap();

        // 3. Reveal permutation
        let permutation = self.reveal_permutations(ctx, step).await.unwrap();
        // TODO(richa) : This is ugly, converted F -> u128 -> usize needed for getting an appropriate Permutation to apply.
        // Besides this makes the code dependent on Permutation struct needs which is not a good design choice.
        let perms: Vec<usize> = permutation.iter().map(|&i| i.as_u128() as usize).collect();

        // 4. apply the permutation on the new permutation
        apply_inv(&mut Permutation::oneline(perms), &mut self.new_permutation);

        // 5. Unshuffle
        let unshuffle_fn = compose_ipa_step!(UnshuffleNewPermutation, step);
        let mut unshuffle_input = Shuffle::new(self.new_permutation, unshuffle_fn);
        let h1_future = unshuffle_input.execute_unshuffle(ctx, &permutations);
        h1_future.await.unwrap();

        Ok(())
    }

    // TODO move this to a shared file after steps are changed
    #[allow(clippy::cast_possible_truncation)]
    async fn reveal_permutations<N: Network<S>, S: Step + SpaceIndex>(
        &self,
        ctx: &ProtocolContext<'_, S, N>,
        step: fn(ComposeStep) -> S,
    ) -> Result<Vec<F>, BoxError> {
        let reveals = self
            .last_permutation
            .iter()
            .enumerate()
            .map(|(index, input)| async move {
                ctx.reveal(
                    RecordId::from(index as u32),
                    step(ComposeStep::RevealPermutation),
                )
                .execute(*input)
                .await
            });
        try_join_all(reveals).await
    }
}

#[cfg(test)]
mod tests {
    use permutation::Permutation;
    use rand::seq::SliceRandom;
    use tokio::try_join;

    use crate::{
        field::Fp31,
        helpers::prss::SpaceIndex,
        protocol::{
            sort::{apply::apply_inv, ComposeStep},
            QueryId, Step,
        },
        test_fixture::{
            generate_shares, make_contexts, make_world, validate_and_reconstruct, TestWorld,
        },
    };

    use super::Compose;

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    enum ComposeTestStep {
        Compose(ComposeStep),
    }

    impl Step for ComposeTestStep {}
    impl SpaceIndex for ComposeTestStep {
        const MAX: usize = ComposeStep::MAX;
        fn as_usize(&self) -> usize {
            match self {
                Self::Compose(s) => s.as_usize(),
            }
        }
    }

    #[tokio::test]
    pub async fn compose() {
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

            let mut sigma_copy = Permutation::oneline(sigma.clone());
            apply_inv(&mut sigma_copy, &mut rho_composed);

            let mut sigma_shares = generate_shares(sigma_u128);
            let mut rho_shares = generate_shares(rho_u128);
            let world: TestWorld<ComposeTestStep> = make_world(QueryId);
            let context = make_contexts(&world);

            let mut compose0 = Compose::new(&mut sigma_shares.0, &mut rho_shares.0);
            let mut compose1 = Compose::new(&mut sigma_shares.1, &mut rho_shares.1);
            let mut compose2 = Compose::new(&mut sigma_shares.2, &mut rho_shares.2);

            let h0_future = compose0.execute(&context[0], ComposeTestStep::Compose);
            let h1_future = compose1.execute(&context[1], ComposeTestStep::Compose);
            let h2_future = compose2.execute(&context[2], ComposeTestStep::Compose);

            try_join!(h0_future, h1_future, h2_future).unwrap();

            assert_eq!(sigma_shares.0.len(), BATCHSIZE);
            assert_eq!(sigma_shares.1.len(), BATCHSIZE);
            assert_eq!(sigma_shares.2.len(), BATCHSIZE);

            // We should get the same result of applying inverse of sigma on rho as in clear
            (0..rho_shares.0.len()).for_each(|i| {
                assert_eq!(
                    validate_and_reconstruct((rho_shares.0[i], rho_shares.1[i], rho_shares.2[i])),
                    Fp31::from(rho_composed[i])
                );
            });
        }
    }
}
