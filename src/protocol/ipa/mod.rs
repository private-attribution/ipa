use std::iter::{repeat, zip};

use crate::{
    error::Error,
    ff::Field,
    protocol::{
        attribution::{
            accumulate_credit::accumulate_credit, credit_capping::credit_capping,
            AttributionInputRow,
        },
        context::Context,
        RecordId,
    },
    secret_sharing::{Replicated, XorReplicated},
};
use futures::future::try_join_all;

use super::context::SemiHonestContext;
use super::modulus_conversion::{convert_all_bits, convert_all_bits_local};
use super::sort::generate_permutation::generate_permutation;
use crate::protocol::boolean::bitwise_equal::bitwise_equal;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    ModulusConversionForMatchKeys,
    GenSortPermutationFromMatchKeys,
    ApplySortPermutation,
    ComputeHelperBits,
    AccumulateCredit,
    PerformUserCapping,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::ModulusConversionForMatchKeys => "mod_conv_match_key",
            Self::GenSortPermutationFromMatchKeys => "gen_sort_permutation_from_match_keys",
            Self::ApplySortPermutation => "apply_sort_permutation",
            Self::ComputeHelperBits => "compute_helper_bits",
            Self::AccumulateCredit => "accumulate_credit",
            Self::PerformUserCapping => "user_capping",
        }
    }
}

/// # Errors
/// Propagates errors from multiplications
#[allow(dead_code)]
pub async fn ipa<F>(
    ctx: SemiHonestContext<'_, F>,
    mk_shares: &[XorReplicated],
    num_bits: u32,
    other_inputs: Vec<Vec<Replicated<F>>>,
    per_user_credit_cap: u32,
) -> Result<Vec<Replicated<F>>, Error>
where
    F: Field,
{
    debug_assert_eq!(mk_shares.len(), other_inputs.len());

    let local_lists = convert_all_bits_local(ctx.role(), mk_shares, num_bits);
    let converted_shares = convert_all_bits(
        &ctx.narrow(&Step::ModulusConversionForMatchKeys),
        &local_lists,
    )
    .await
    .unwrap();
    let sort_permutation = generate_permutation(
        ctx.narrow(&Step::GenSortPermutationFromMatchKeys),
        &converted_shares,
        num_bits,
    )
    .await
    .unwrap();

    let num_bits: usize = usize::try_from(num_bits).unwrap();

    let combined_match_keys_and_sidecar_data = other_inputs
        .into_iter()
        .enumerate()
        .map(|(row_index, mut sidecar_data)| {
            for i in 0..num_bits {
                sidecar_data.push(converted_shares[i][row_index].clone());
            }
            sidecar_data
        })
        .collect::<Vec<_>>();

    let sorted_rows = sort_permutation
        .apply(
            ctx.narrow(&Step::ApplySortPermutation),
            combined_match_keys_and_sidecar_data,
        )
        .await
        .unwrap();

    let futures = zip(
        repeat(ctx.narrow(&Step::ComputeHelperBits)),
        sorted_rows.iter(),
    )
    .zip(sorted_rows.iter().skip(1))
    .enumerate()
    .map(|(i, ((ctx, row), next_row))| {
        let record_id = RecordId::from(i);
        async move { bitwise_equal(ctx, record_id, &row[3..], &next_row[3..]).await }
    });
    let helper_bits = try_join_all(futures).await?;

    let attribution_input_rows = sorted_rows
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let hb = if i == 0 {
                Replicated::ZERO
            } else {
                helper_bits[i - 1].clone()
            };
            AttributionInputRow {
                is_trigger_bit: row[0].clone(),
                helper_bit: hb,
                breakdown_key: row[1].clone(),
                credit: row[2].clone(),
            }
        })
        .collect::<Vec<_>>();

    let accumulated_credits =
        accumulate_credit(ctx.narrow(&Step::AccumulateCredit), &attribution_input_rows).await?;

    let _user_capped_credits = credit_capping(
        ctx.narrow(&Step::PerformUserCapping),
        &accumulated_credits,
        per_user_credit_cap,
    )
    .await?;

    Ok(helper_bits)
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::ipa;
    use crate::{
        ff::{Field, Fp32BitPrime},
        protocol::QueryId,
        test_fixture::{MaskedMatchKey, Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn semi_honest() {
        const COUNT: usize = 5;

        let world = TestWorld::new(QueryId);

        //   match key, is_trigger, breakdown_key, trigger_value
        let records = [
            [12345_u64, 0, 1, 0],
            [12345_u64, 0, 2, 0],
            [68362_u64, 0, 1, 0],
            [12345_u64, 1, 0, 5],
            [68362_u64, 1, 0, 2],
        ];
        let match_keys = records
            .iter()
            .map(|record| MaskedMatchKey::mask(record[0]))
            .collect::<Vec<_>>();

        let other_inputs = records
            .iter()
            .map(|record| {
                let c = Fp32BitPrime::from;
                [c(record[1]), c(record[2]), c(record[3])]
            })
            .collect::<Vec<_>>();

        let result = world
            .semi_honest(
                (match_keys, other_inputs),
                |ctx, (mk_shares, shares_of_other_inputs)| async move {
                    ipa(ctx, &mk_shares, 20, shares_of_other_inputs, 3)
                        .await
                        .unwrap()
                },
            )
            .await;

        let helper_bits = result.reconstruct();
        assert_eq!(
            helper_bits,
            vec![
                Fp32BitPrime::ONE,
                Fp32BitPrime::ONE,
                Fp32BitPrime::ZERO,
                Fp32BitPrime::ONE,
            ]
        );
    }
}
