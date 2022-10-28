use crate::{
    error::BoxError,
    ff::Field,
    helpers::fabric::Network,
    protocol::{
        context::ProtocolContext,
        reveal::reveal,
        sort::ApplyInvStep::{RevealPermutation, ShuffleInputs, ShufflePermutation},
        RecordId,
    },
    secret_sharing::Replicated,
};
use embed_doc_image::embed_doc_image;
use futures::future::try_join_all;
use permutation::Permutation;

use super::{
    apply::apply,
    shuffle::{generate_random_permutation, Shuffle},
};
use tokio::try_join;

/// This is APPLYINV(Algorithm 4) described in <https://eprint.iacr.org/2019/695.pdf>.
/// This is a protocol that applies the inverse of a shared permutation to a shared-vector representation.
/// Input: Each helpers know their own secret shares of input and permutation
/// Output: At the end of the protocol, all helpers receive inputs after the permutation is applied
#[derive(Debug)]
#[embed_doc_image("secureapplyinv", "images/sort/secureapplyinv.png")]
pub struct SecureApplyInv<'a, F> {
    input: &'a mut Vec<Replicated<F>>,
    permutation: &'a mut Vec<Replicated<F>>,
}

impl<'a, F: Field> SecureApplyInv<'a, F> {
    #[allow(dead_code)]
    pub fn new(input: &'a mut Vec<Replicated<F>>, permutation: &'a mut Vec<Replicated<F>>) -> Self {
        Self { input, permutation }
    }
    /// This algorithm applies a permutation on the inputs. The permutation is not available in clear and
    /// we do not want to reveal the actual permutation to any of the helpers while applying it.
    /// Steps
    /// ![Secure Apply Inv steps][secureapplyinv]
    /// 1. Generate a permutation
    /// 2. Secret shared permutation is shuffled with a permutation
    /// 3. Secret shared value is shuffled using the same permutation as 1
    /// 4. The permutation is revealed
    /// 5. All helpers call `apply` to apply the permutation locally.
    #[allow(dead_code)]
    pub async fn execute(
        &mut self,
        ctx: &ProtocolContext<'_, F>,
    ) -> Result<(), BoxError> {
        // 1. Generate permutation
        let permutations = generate_random_permutation(self.input.len(), &ctx.prss());
        // 2. Shuffle permutations
        let mut shuffle_permutation = Shuffle::new(self.permutation);
        let h0_future = shuffle_permutation.execute(ctx.narrow(&ShufflePermutation), &permutations);

        // 3. Shuffle inputs
        let mut shuffle_input = Shuffle::new(self.input);
        let h1_future = shuffle_input.execute(ctx.narrow(&ShuffleInputs), &permutations);

        try_join!(h0_future, h1_future).unwrap();

        // 4. Reveal permutation to all helpers
        let permutation = self
            .reveal_permutations(&ctx.narrow(&RevealPermutation))
            .await
            .unwrap();
        let mut perms = Vec::new();
        // TODO(richa) : This is ugly, converted F -> u128 -> usize needed for getting an appropriate Permutation to apply.
        // Besides this makes the code dependent on Permutation struct needs which is not a good design choice.
        for i in &permutation {
            perms.push(i.as_u128() as usize);
        }
        let mut permutation = Permutation::oneline(perms);

        // 5. apply the permutation on the shuffled input
        // The paper suggests taking apply_inv. However, Permutation::oneline returns an inverted permutation, so we are negating
        // the effect by just calling apply instead of apply_inv here
        apply(&mut permutation, &mut self.input);
        Ok(())
    }

    #[allow(clippy::cast_possible_truncation)]
    async fn reveal_permutations(
        &self,
        ctx: &ProtocolContext<'_, F>,
    ) -> Result<Vec<F>, BoxError> {
        let reveals = self
            .permutation
            .iter()
            .enumerate()
            .map(|(index, input)| async move {
                reveal(
                    ctx.narrow(&index.to_string()),
                    RecordId::from(index as u32),
                    *input,
                )
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
        ff::Fp31,
        protocol::{sort::apply::apply_inv, QueryId},
        test_fixture::{generate_shares, make_contexts, make_world, validate_and_reconstruct},
    };

    use super::SecureApplyInv;

    #[tokio::test]
    pub async fn secureapplyinv() {
        const BATCHSIZE: usize = 25;
        for _ in 0..10 {
            let mut rng = rand::thread_rng();
            let mut input = [0u128; BATCHSIZE];
            random_number::random_fill!(input, 0..24);

            let mut permutation: Vec<usize> = (0..BATCHSIZE).collect();
            permutation.shuffle(&mut rng);

            let mut expected_result = input;
            let mut cloned_perm = Permutation::oneline(permutation.clone()).inverse();

            apply_inv(&mut cloned_perm, &mut expected_result);

            let permutation: Vec<u128> = permutation.iter().map(|x| *x as u128).collect();

            let mut perm_shares = generate_shares(permutation);
            let mut input_shares = generate_shares(input.to_vec());

            let world = make_world(QueryId);
            let context = make_contexts(&world);

            let mut secure_applyinv0 = SecureApplyInv::new(&mut input_shares.0, &mut perm_shares.0);
            let mut secure_applyinv1 = SecureApplyInv::new(&mut input_shares.1, &mut perm_shares.1);
            let mut secure_applyinv2 = SecureApplyInv::new(&mut input_shares.2, &mut perm_shares.2);

            let h0_future = secure_applyinv0.execute(&context[0]);
            let h1_future = secure_applyinv1.execute(&context[1]);
            let h2_future = secure_applyinv2.execute(&context[2]);

            try_join!(h0_future, h1_future, h2_future).unwrap();

            assert_eq!(input_shares.0.len(), BATCHSIZE);
            assert_eq!(input_shares.1.len(), BATCHSIZE);
            assert_eq!(input_shares.2.len(), BATCHSIZE);

            // We should get the same result of applying inverse as what we get when applying in clear
            (0..input_shares.0.len()).for_each(|i| {
                assert_eq!(
                    validate_and_reconstruct((
                        input_shares.0[i],
                        input_shares.1[i],
                        input_shares.2[i]
                    )),
                    Fp31::from(expected_result[i])
                );
            });
        }
    }
}
