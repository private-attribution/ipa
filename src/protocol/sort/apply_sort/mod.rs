pub mod shuffle;

use async_trait::async_trait;

use crate::{
    error::Error,
    ff::Field,
    protocol::{
        context::{Context, MaliciousContext, SemiHonestContext},
        sort::{apply::apply_inv, generate_permutation::shuffle_and_reveal_permutation},
    },
    secret_sharing::{MaliciousReplicated, Replicated, SecretSharing},
};

use crate::protocol::sort::ApplyInvStep::ShuffleInputs;
use crate::protocol::sort::SortStep::ShuffleRevealPermutation;

use self::shuffle::{shuffle_shares, Resharable};

#[derive(Debug)]
pub struct SortPermutation<F: Field>(pub Vec<Replicated<F>>);

#[async_trait]
pub trait ApplySort<F: Field> {
    /// Secret sharing type that apply implementation works with.
    type Share: SecretSharing<F>;

    /// This trait applies a sort permutation to the received input
    async fn apply<I>(
        self,
        input: Vec<I>,
        sort_permutation: SortPermutation<F>,
    ) -> Result<Vec<I>, Error>
    where
        F: Field,
        I: Resharable<F, Share = Self::Share> + Send + Sync;
}

#[async_trait]
impl<F: Field> ApplySort<F> for SemiHonestContext<'_, F> {
    type Share = Replicated<F>;

    async fn apply<I>(
        self,
        input: Vec<I>,
        sort_permutation: SortPermutation<F>,
    ) -> Result<Vec<I>, Error>
    where
        F: Field,
        I: Resharable<F, Share = Self::Share> + Send + Sync,
    {
        let revealed_and_random_permutation = shuffle_and_reveal_permutation(
            self.narrow(&ShuffleRevealPermutation),
            input.len().try_into().unwrap(),
            sort_permutation.0,
        )
        .await?;

        let mut shuffled_objects = shuffle_shares(
            input,
            (
                &revealed_and_random_permutation.randoms_for_shuffle.0,
                &revealed_and_random_permutation.randoms_for_shuffle.1,
            ),
            self.narrow(&ShuffleInputs),
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
/// This trait applies a sort permutation to the received input. We expect sort_permutation to be received
/// as Replicated and it is the responsibility of caller to upgrade to malicious before applying the sort permutation
impl<F: Field> ApplySort<F> for MaliciousContext<'_, F> {
    type Share = MaliciousReplicated<F>;

    async fn apply<I>(
        self,
        input: Vec<I>,
        sort_permutation: SortPermutation<F>,
    ) -> Result<Vec<I>, Error>
    where
        F: Field,
        I: Resharable<F, Share = Self::Share> + Send + Sync,
    {
        let revealed_and_random_permutation = shuffle_and_reveal_permutation(
            self.narrow(&ShuffleRevealPermutation),
            input.len().try_into().unwrap(),
            self.upgrade_vec(sort_permutation.0).await?,
        )
        .await?;

        let mut shuffled_objects = shuffle_shares(
            input,
            (
                &revealed_and_random_permutation.randoms_for_shuffle.0,
                &revealed_and_random_permutation.randoms_for_shuffle.1,
            ),
            self.narrow(&ShuffleInputs),
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
    use rand::seq::SliceRandom;

    use crate::protocol::attribution::accumulate_credit::tests::AttributionTestInput;
    use crate::protocol::context::Context;
    use crate::protocol::modulus_conversion::{convert_all_bits, convert_all_bits_local};
    use crate::protocol::sort::apply_sort::{ApplySort, SortPermutation};
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
                    ctx.apply(secret, sort_permutation).await.unwrap()
                },
            )
            .await;
        assert_eq!(&expected[..], &result.reconstruct()[..]);
    }

    #[tokio::test]
    pub async fn malicious() {
        const COUNT: u128 = 10;

        let world = TestWorld::new(QueryId);
        let mut rng = thread_rng();
        let mut sort_permutation = (0..COUNT).collect::<Vec<u128>>();
        sort_permutation.shuffle(&mut thread_rng());

        let mut sidecar: Vec<AttributionTestInput<Fp32BitPrime>> =
            Vec::with_capacity(COUNT.try_into().unwrap());
        sidecar.resize_with(COUNT.try_into().unwrap(), || {
            AttributionTestInput([(); 4].map(|_| rng.gen::<Fp32BitPrime>()))
        });
        let permutation = permutation::sort(sort_permutation.clone());
        let expected = permutation.apply_slice(&sidecar);

        let sort_permutation: Vec<_> = sort_permutation
            .iter()
            .map(|x| Fp32BitPrime::from(*x))
            .collect();

        let result = world
            .semi_honest(
                (sort_permutation, sidecar),
                |ctx, (sort_permutation, secret)| async move {
                    ctx.apply(secret, SortPermutation(sort_permutation))
                        .await
                        .unwrap()
                },
            )
            .await;
        assert_eq!(&expected[..], &result.reconstruct()[..]);
    }
}
