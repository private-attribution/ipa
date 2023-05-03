use crate::{
    error::Error,
    protocol::{basics::Reshare, context::Context, sort::ApplyInvStep::ShuffleInputs, RecordId},
};

use super::{apply::apply_inv, apply_sort::shuffle_shares as shuffle_vectors};

pub async fn secureapplyinv_multi<C: Context, I: Reshare<C, RecordId> + Send + Sync>(
    ctx: C,
    input: Vec<I>,
    random_permutations_for_shuffle: (&[u32], &[u32]),
    shuffled_sort_permutation: &[u32],
) -> Result<Vec<I>, Error> {
    let mut shuffled_input = shuffle_vectors(
        input,
        random_permutations_for_shuffle,
        ctx.narrow(&ShuffleInputs),
    )
    .await?;

    apply_inv(shuffled_sort_permutation, &mut shuffled_input);
    Ok(shuffled_input)
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    mod semi_honest {
        use rand::seq::SliceRandom;

        use crate::{
            ff::{Field, Fp31},
            protocol::{
                context::{Context, SemiHonestContext, UpgradableContext, Validator},
                sort::{
                    apply::apply_inv, generate_permutation::shuffle_and_reveal_permutation,
                    secureapplyinv::secureapplyinv_multi,
                },
            },
            rand::Rng,
            test_fixture::{Reconstruct, Runner, TestWorld},
        };

        #[tokio::test]
        pub async fn multi() {
            const BATCHSIZE: u32 = 25;
            const NUM_MULTI_BITS: u32 = 3;
            let world = TestWorld::default();
            let mut rng = rand::thread_rng();

            let mut input = Vec::with_capacity(NUM_MULTI_BITS.try_into().unwrap());
            for _ in 0..BATCHSIZE {
                let mut one_record = Vec::with_capacity(BATCHSIZE as usize);
                one_record.resize_with(NUM_MULTI_BITS.try_into().unwrap(), || rng.gen::<Fp31>());
                input.push(one_record);
            }

            let mut permutation: Vec<u32> = (0..BATCHSIZE).collect();
            permutation.shuffle(&mut rng);

            let mut expected_result = input.clone();

            // Applying permutation on the input in clear to get the expected result
            apply_inv(&permutation, &mut expected_result);

            let permutation_iter = permutation
                .into_iter()
                .map(u128::from)
                .map(Fp31::truncate_from);

            let result = world
                .semi_honest(
                    (input, permutation_iter),
                    |ctx, (m_shares, m_perms)| async move {
                        let v = ctx.narrow("shuffle_reveal").validator();
                        let perm_and_randoms = shuffle_and_reveal_permutation::<
                            SemiHonestContext,
                            _,
                            _,
                        >(v.context(), m_perms, v)
                        .await
                        .unwrap();
                        secureapplyinv_multi(
                            ctx,
                            m_shares,
                            (
                                perm_and_randoms.randoms_for_shuffle.0.as_slice(),
                                perm_and_randoms.randoms_for_shuffle.1.as_slice(),
                            ),
                            &perm_and_randoms.revealed,
                        )
                        .await
                        .unwrap()
                    },
                )
                .await;

            assert_eq!(&expected_result[..], &result.reconstruct());
        }
    }
}
