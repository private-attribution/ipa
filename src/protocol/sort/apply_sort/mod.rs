pub mod shuffle;

use async_trait::async_trait;
use futures::future::try_join_all;

use crate::{
    error::Error,
    ff::Field,
    helpers::Role,
    protocol::{
        context::{Context, SemiHonestContext},
        sort::{apply::apply_inv, generate_permutation::shuffle_and_reveal_permutation},
        BitOpStep, RecordId,
    },
    secret_sharing::Replicated,
};

use crate::protocol::sort::ApplyInvStep::ShuffleInputs;
use crate::protocol::sort::SortStep::ShuffleRevealPermutation;

use self::shuffle::{shuffle_shares, Resharable};

#[derive(Debug)]
pub struct SortPermutation<F: Field>(pub Vec<Replicated<F>>);

impl<F: Field> SortPermutation<F> {
    #[allow(dead_code)]
    /// ## Panics
    /// It will propagate panics from sort
    /// # Errors
    /// it will propagate errors from sort
    pub async fn apply<I>(
        self,
        ctx: SemiHonestContext<'_, F>,
        input: Vec<I>,
    ) -> Result<Vec<I>, Error>
    where
        I: Resharable,
    {
        let revealed_and_random_permutation = shuffle_and_reveal_permutation(
            ctx.narrow(&ShuffleRevealPermutation),
            input.len().try_into().unwrap(),
            self.0,
        )
        .await?;

        let mut shuffled_objects = shuffle_shares(
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

#[async_trait]
impl<T> Resharable for Vec<T>
where
    T: Resharable,
{
    async fn reshare<F, C>(
        &self,
        ctx: C,
        record_id: RecordId,
        to_helper: Role,
    ) -> Result<Self, Error>
    where
        F: Field,
        C: Context<F> + Send,
    {
        try_join_all(self.iter().enumerate().map(|(i, x)| {
            let c = ctx.narrow(BitOpStep::from(i));
            async move { c.reshare(x, record_id, to_helper).await }
        }))
        .await
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use crate::protocol::attribution::accumulate_credit::tests::AttributionTestInput;
    use crate::protocol::context::Context;
    use crate::protocol::modulus_conversion::{convert_all_bits, convert_all_bits_local};
    use crate::protocol::sort::generate_permutation::generate_permutation;
    use crate::protocol::IpaProtocolStep::SortPreAccumulation;
    use crate::protocol::QueryId;
    use crate::rand::{thread_rng, Rng};
    use crate::test_fixture::{MaskedMatchKey, Reconstruct, Runner};
    use crate::{ff::Fp32BitPrime, test_fixture::TestWorld};
    #[tokio::test]
    pub async fn semi_honest() {
        const COUNT: usize = 5;

        let world = TestWorld::new(QueryId);
        let mut rng = thread_rng();

        let mut match_keys = Vec::with_capacity(COUNT);
        match_keys.resize_with(COUNT, || MaskedMatchKey::mask(rng.gen()));

        let permutation = permutation::sort(
            match_keys
                .iter()
                .map(|mk| u64::from(*mk))
                .collect::<Vec<_>>(),
        );

        let mut sidecar: Vec<AttributionTestInput<Fp32BitPrime>> = Vec::with_capacity(COUNT);
        sidecar.resize_with(COUNT, || {
            AttributionTestInput([(); 4].map(|_| rng.gen::<Fp32BitPrime>()))
        });
        let expected = permutation.apply_slice(&sidecar);

        let result = world
            .semi_honest(
                (match_keys, sidecar),
                |ctx, (mk_shares, secret)| async move {
                    let local_lists =
                        convert_all_bits_local(ctx.role(), &mk_shares, MaskedMatchKey::BITS);
                    let converted_shares =
                        convert_all_bits(&ctx.narrow("convert_all_bits"), &local_lists)
                            .await
                            .unwrap();
                    let sort_permutation = generate_permutation(
                        ctx.narrow(&SortPreAccumulation),
                        &converted_shares,
                        MaskedMatchKey::BITS,
                    )
                    .await
                    .unwrap();
                    sort_permutation.apply(ctx, secret).await.unwrap()
                },
            )
            .await;
        assert_eq!(&expected[..], &result.reconstruct()[..]);
    }
}
