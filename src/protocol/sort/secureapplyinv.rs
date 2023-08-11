use crate::{
    error::Error,
    protocol::{
        basics::Reshare,
        context::Context,
        sort::{
            apply::apply_inv, apply_sort::shuffle_shares as shuffle_vectors,
            ApplyInvStep::ShuffleInputs,
        },
        RecordId,
    },
};

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

#[cfg(all(test, unit_test))]
mod tests {
    mod semi_honest {
        use std::iter::repeat_with;

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
            rand::{thread_rng, Rng},
            secret_sharing::BitDecomposed,
            test_fixture::{Reconstruct, Runner, TestWorld},
        };

        #[tokio::test]
        pub async fn multi() {
            const BATCHSIZE: usize = 25;
            const NUM_MULTI_BITS: usize = 3;
            let world = TestWorld::default();

            let input = repeat_with(|| {
                BitDecomposed::new(repeat_with(|| thread_rng().gen::<Fp31>()).take(NUM_MULTI_BITS))
            })
            .take(BATCHSIZE)
            .collect::<Vec<_>>();

            let mut permutation: Vec<u32> = (0..u32::try_from(BATCHSIZE).unwrap()).collect();
            permutation.shuffle(&mut thread_rng());

            let mut expected_result = input.clone();

            // Applying permutation on the input in clear to get the expected result
            apply_inv(&permutation, &mut expected_result);

            let permutation_iter = permutation
                .into_iter()
                .map(u128::from)
                .map(Fp31::truncate_from);

            // Flatten the input so that it can implement `IntoShares`.
            let result = world
                .semi_honest(
                    (input.into_iter(), permutation_iter),
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
