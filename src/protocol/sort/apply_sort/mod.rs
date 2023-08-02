pub mod shuffle;

pub use shuffle::shuffle_shares;

use crate::{
    error::Error,
    protocol::{
        basics::Reshare,
        context::Context,
        sort::{
            apply::apply_inv, generate_permutation::RevealedAndRandomPermutations,
            ApplyInvStep::ShuffleInputs,
        },
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
    use crate::{
        accumulation_test_input,
        ff::{Fp31, Fp32BitPrime, GaloisField},
        protocol::{
            attribution::input::{AccumulateCreditInputRow, MCAccumulateCreditInputRow},
            context::Context,
            modulus_conversion::{convert_all_bits, convert_all_bits_local},
            sort::{
                apply_sort::apply_sort_permutation,
                generate_permutation::generate_permutation_and_reveal_shuffled,
            },
            BreakdownKey, MatchKey,
        },
        rand::{thread_rng, Rng},
        secret_sharing::{replicated::semi_honest::AdditiveShare, SharedValue},
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
                    breakdown_key: rng.gen::<u8>(),
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
                    Vec<AdditiveShare<MatchKey>>,
                    Vec<AccumulateCreditInputRow<Fp32BitPrime, BreakdownKey>>,
                )| async move {
                    let local_lists =
                        convert_all_bits_local::<Fp31, _>(ctx.role(), mk_shares.into_iter());
                    let converted_shares = convert_all_bits(
                        &ctx.narrow("convert_all_bits"),
                        &local_lists,
                        MatchKey::BITS,
                        NUM_MULTI_BITS,
                    )
                    .await
                    .unwrap();
                    let sort_permutation = generate_permutation_and_reveal_shuffled(
                        ctx.narrow("sort_pre_accumulation"),
                        converted_shares.iter(),
                    )
                    .await
                    .unwrap();

                    let bk_shares = secret.iter().map(|x| x.breakdown_key.clone());

                    let mut converted_bk_shares = convert_all_bits(
                        &ctx,
                        &convert_all_bits_local(ctx.role(), bk_shares),
                        BreakdownKey::BITS,
                        BreakdownKey::BITS,
                    )
                    .await
                    .unwrap();
                    let converted_bk_shares = converted_bk_shares.pop().unwrap();

                    let converted_secret = secret
                        .into_iter()
                        .zip(converted_bk_shares)
                        .map(|(row, bk)| {
                            MCAccumulateCreditInputRow::new(
                                row.is_trigger_report,
                                row.helper_bit,
                                row.active_bit,
                                bk,
                                row.trigger_value,
                            )
                        })
                        .collect::<Vec<_>>();

                    apply_sort_permutation(ctx, converted_secret, &sort_permutation)
                        .await
                        .unwrap()
                },
            )
            .await
            .reconstruct();

        assert_eq!(&expected[..], &result[..]);
    }
}
