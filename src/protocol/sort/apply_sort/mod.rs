pub mod shuffle;

use crate::{
    error::Error,
    ff::Field,
    protocol::{context::Context, sort::apply::apply_inv},
    secret_sharing::SecretSharing,
};

use crate::protocol::sort::ApplyInvStep::ShuffleInputs;

pub use self::shuffle::{shuffle_shares, Resharable};

use super::generate_permutation::RevealedAndRandomPermutations;

/// # Errors
/// Propagates errors from shuffle/reshare
pub async fn apply_sort_permutation<C, F, S, I>(
    ctx: C,
    input: Vec<I>,
    sort_permutation: &RevealedAndRandomPermutations,
) -> Result<Vec<I>, Error>
where
    C: Context<F, Share = S>,
    F: Field,
    S: SecretSharing<F>,
    I: Resharable<F, Share = S> + Send + Sync,
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

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {

    use std::marker::PhantomData;

    use crate::accumulation_test_input;
    use crate::bits::BitArray;
    use crate::protocol::attribution::input::{
        AccumulateCreditInputRow, MCAccumulateCreditInputRow,
    };
    use crate::protocol::context::Context;
    use crate::protocol::modulus_conversion::{
        combine_slices, convert_all_bits, convert_all_bits_local,
    };
    use crate::protocol::sort::apply_sort::apply_sort_permutation;
    use crate::protocol::sort::generate_permutation::generate_permutation_and_reveal_shuffled;
    use crate::protocol::IpaProtocolStep::SortPreAccumulation;
    use crate::protocol::{BreakdownKey, MatchKey};
    use crate::rand::{thread_rng, Rng};
    use crate::secret_sharing::replicated::semi_honest::XorShare;
    use crate::secret_sharing::SharedValue;
    use crate::test_fixture::input::GenericReportTestInput;
    use crate::test_fixture::{Reconstruct, Runner};
    use crate::{ff::Fp32BitPrime, test_fixture::TestWorld};

    #[tokio::test]
    pub async fn semi_honest() {
        const COUNT: usize = 5;
        const NUM_MULTI_BITS: u32 = 3;

        let world = TestWorld::new().await;
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
                    breakdown_key: rng.gen::<u8>(),
                    credit: rng.gen::<u8>(),
                };
                (Fp32BitPrime, MathKey, BreakdownKey)
            )
        });
        let expected = permutation.apply_slice(&sidecar);

        let result: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = world
            .semi_honest(
                (match_keys, sidecar),
                |ctx,
                 (mk_shares, secret): (
                    Vec<XorShare<MatchKey>>,
                    Vec<AccumulateCreditInputRow<Fp32BitPrime, BreakdownKey>>,
                )| async move {
                    let local_lists = convert_all_bits_local(ctx.role(), &mk_shares);
                    let converted_shares = convert_all_bits(
                        &ctx.narrow("convert_all_bits"),
                        &local_lists,
                        MatchKey::BITS,
                        NUM_MULTI_BITS,
                    )
                    .await
                    .unwrap();
                    let sort_permutation = generate_permutation_and_reveal_shuffled(
                        ctx.narrow(&SortPreAccumulation),
                        converted_shares.iter(),
                    )
                    .await
                    .unwrap();

                    let bk_shares = secret
                        .iter()
                        .map(|x| x.breakdown_key.clone())
                        .collect::<Vec<_>>();
                    let converted_bk_shares = convert_all_bits(
                        &ctx,
                        &convert_all_bits_local(ctx.role(), &bk_shares),
                        BreakdownKey::BITS,
                        NUM_MULTI_BITS,
                    )
                    .await
                    .unwrap();
                    let converted_bk_shares =
                        combine_slices(converted_bk_shares.iter(), COUNT, BreakdownKey::BITS);

                    let converted_secret = secret
                        .into_iter()
                        .zip(converted_bk_shares)
                        .map(|(row, bk)| MCAccumulateCreditInputRow {
                            is_trigger_report: row.is_trigger_report,
                            breakdown_key: bk,
                            trigger_value: row.trigger_value,
                            helper_bit: row.helper_bit,
                            _marker: PhantomData::default(),
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
