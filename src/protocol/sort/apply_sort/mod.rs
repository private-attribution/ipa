pub mod shuffle;

pub use shuffle::shuffle_shares;

use crate::{
    error::Error,
    protocol::{
        basics::{apply_permutation::apply_inv, Reshare},
        context::Context,
        sort::{generate_permutation::RevealedAndRandomPermutations, ApplyInvStep::ShuffleInputs},
        RecordId,
    },
};

/// # Errors
/// Propagates errors from shuffle/reshare
#[tracing::instrument(name = "apply_sort", skip_all, fields(gate = %ctx.gate().as_ref()))]
pub async fn apply_sort_permutation<C, I>(
    ctx: C,
    input: Vec<I>,
    sort_permutation: &RevealedAndRandomPermutations,
) -> Result<Vec<I>, Error>
where
    C: Context,
    I: Reshare<C, RecordId> + Send + Sync,
{
    let mut shuffled_objects = shuffle_shares(
        input,
        (
            &sort_permutation.randoms_for_shuffle.0,
            &sort_permutation.randoms_for_shuffle.1,
        ),
        ctx.narrow(&ShuffleInputs),
    )
    .await?;

    apply_inv(&sort_permutation.revealed, &mut shuffled_objects);
    Ok(shuffled_objects)
}

#[cfg(all(test, unit_test))]
mod tests {
    use futures::stream::iter as stream_iter;

    use crate::{
        accumulation_test_input,
        ff::{Fp32BitPrime, GaloisField},
        protocol::{
            attribution::input::AccumulateCreditInputRow,
            context::Context,
            sort::{
                apply_sort::apply_sort_permutation,
                generate_permutation::generate_permutation_and_reveal_shuffled,
            },
            BreakdownKey, MatchKey,
        },
        rand::{thread_rng, Rng},
        secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, SharedValue},
        test_fixture::{input::GenericReportTestInput, Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn semi_honest() {
        const COUNT: usize = 5;
        const NUM_MULTI_BITS: u32 = 3;

        let world = TestWorld::default();
        let mut rng = thread_rng();

        let mut match_keys = Vec::with_capacity(COUNT);
        match_keys.resize_with(COUNT, || rng.gen::<MatchKey>());

        let permutation =
            permutation::sort(match_keys.iter().map(|mk| mk.as_u128()).collect::<Vec<_>>());

        let mut sidecar: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> =
            Vec::with_capacity(COUNT);
        sidecar.resize_with(COUNT, || {
            accumulation_test_input!(
                {
                    is_trigger_report: rng.gen::<u8>(),
                    helper_bit: rng.gen::<u8>(),
                    active_bit: rng.gen::<u8>(),
                    credit: rng.gen::<u8>(),
                };
                (Fp32BitPrime, MathKey, BreakdownKey)
            )
        });
        let expected = permutation.apply_slice(&sidecar);

        let result: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = world
            .semi_honest(
                (match_keys.into_iter(), sidecar.into_iter()),
                |ctx,
                 (mk_shares, secret): (
                    Vec<Replicated<MatchKey>>,
                    Vec<AccumulateCreditInputRow<Fp32BitPrime, Replicated<_>>>,
                )| async move {
                    let ctx = ctx.narrow("apply_sort");
                    let sort_permutation =
                        generate_permutation_and_reveal_shuffled::<Fp32BitPrime, _, _, _>(
                            ctx.narrow("convert_all_bits"),
                            stream_iter(mk_shares),
                            NUM_MULTI_BITS,
                            MatchKey::BITS,
                        )
                        .await
                        .unwrap();

                    apply_sort_permutation(ctx, secret, &sort_permutation)
                        .await
                        .unwrap()
                },
            )
            .await
            .reconstruct();

        assert_eq!(&expected[..], &result[..]);
    }
}
