use crate::{
    error::Error,
    ff::Field,
    protocol::{
        context::{Context, SemiHonestContext},
        sort::{apply::apply_inv, generate_permutation::shuffle_and_reveal_permutation},
    },
    secret_sharing::Replicated,
};

use super::shuffle_objects::{shuffle_object_shares, Resharable};
use crate::protocol::sort::ApplyInvStep::ShuffleInputs;
use crate::protocol::sort::SortStep::ShuffleRevealPermutation;

#[derive(Debug)]
pub struct SortPermutation<F: Field>(pub Vec<Replicated<F>>);

impl<F: Field> SortPermutation<F> {
    #[allow(dead_code)]
    /// ## Panics
    /// It will propagate panics from sort
    /// # Errors
    /// it will propagate errors from sort
    pub async fn apply_sort_permutation<I>(
        self,
        ctx: SemiHonestContext<'_, F>,
        input: Vec<I>,
    ) -> Result<Vec<I>, Error>
    where
        I: Resharable<F, Share = Replicated<F>>,
    {
        let revealed_and_random_permutation = shuffle_and_reveal_permutation(
            ctx.narrow(&ShuffleRevealPermutation),
            input.len().try_into().unwrap(),
            self.0,
        )
        .await?;

        let mut shuffled_objects = shuffle_object_shares(
            input,
            (
                &revealed_and_random_permutation.randoms_for_shuffle.0,
                &revealed_and_random_permutation.randoms_for_shuffle.1,
            ),
            ctx.narrow(&ShuffleInputs),
        )
        .await?;

        apply_inv(
            &revealed_and_random_permutation.revealed,
            &mut shuffled_objects,
        );
        Ok(shuffled_objects)
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use crate::protocol::attribution::accumulate_credit::tests::FAttributionInputRow;
    use crate::protocol::attribution::AttributionInputRow;
    use crate::protocol::context::Context;
    use crate::protocol::sort::generate_permutation::generate_permutation;
    use crate::protocol::IpaProtocolStep::SortPreAccumulation;
    use crate::protocol::QueryId;
    use crate::rand::{thread_rng, Rng};
    use crate::secret_sharing::XorReplicated;
    use crate::test_fixture::{MaskedMatchKey, Reconstruct, Runner};
    use crate::{ff::Fp32BitPrime, test_fixture::TestWorld};
    #[tokio::test]
    pub async fn semi_honest() {
        const COUNT: usize = 5;

        let world = TestWorld::<Fp32BitPrime>::new(QueryId);
        let mut rng = thread_rng();

        let mut match_keys = Vec::with_capacity(COUNT);
        match_keys.resize_with(COUNT, || MaskedMatchKey::mask(rng.gen()));

        let permutation = permutation::sort(
            match_keys
                .iter()
                .map(|mk| u64::from(*mk))
                .collect::<Vec<_>>(),
        );

        let mut sidecar: Vec<FAttributionInputRow<Fp32BitPrime>> = Vec::with_capacity(COUNT);
        sidecar.resize_with(COUNT, || {
            FAttributionInputRow([(); 4].map(|_| rng.gen::<Fp32BitPrime>()))
        });
        let expected = permutation.apply_slice(&sidecar);

        let result = world
            .semi_honest(
                (match_keys, sidecar),
                |ctx,
                 (mk_shares, secret): (
                    Vec<XorReplicated>,
                    Vec<AttributionInputRow<Fp32BitPrime>>,
                )| async move {
                    let sort_permutation = generate_permutation(
                        ctx.narrow(&SortPreAccumulation),
                        &mk_shares,
                        MaskedMatchKey::BITS,
                    )
                    .await
                    .unwrap();
                    sort_permutation
                        .apply_sort_permutation(ctx, secret)
                        .await
                        .unwrap()
                },
            )
            .await;
        assert_eq!(&expected[..], &result.reconstruct());
    }
}
