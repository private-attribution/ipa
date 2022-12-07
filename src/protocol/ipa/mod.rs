use std::iter::{repeat, zip};

use crate::{
    error::Error,
    ff::Field,
    protocol::{
        attribution::{
            accumulate_credit::accumulate_credit, aggregate_credit::aggregate_credit,
            credit_capping::credit_capping, AttributionInputRow,
        },
        context::Context,
        sort::{
            apply_sort::apply_sort_permutation,
            generate_permutation::generate_permutation_and_reveal_shuffled,
        },
        RecordId,
    },
    secret_sharing::{Replicated, XorReplicated},
};
use futures::future::try_join_all;

use super::modulus_conversion::{convert_all_bits, convert_all_bits_local};
use super::{attribution::AggregateCreditOutputRow, context::SemiHonestContext};
use crate::protocol::boolean::bitwise_equal::bitwise_equal;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    ModulusConversionForMatchKeys,
    GenSortPermutationFromMatchKeys,
    ApplySortPermutation,
    ComputeHelperBits,
    AccumulateCredit,
    PerformUserCapping,
    AggregateCredit,
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
            Self::AggregateCredit => "aggregate_credit",
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
) -> Result<Vec<AggregateCreditOutputRow<F>>, Error>
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
    let sort_permutation = generate_permutation_and_reveal_shuffled(
        ctx.narrow(&Step::GenSortPermutationFromMatchKeys),
        &converted_shares,
        num_bits,
    )
    .await
    .unwrap();

    let combined_match_keys_and_sidecar_data = other_inputs
        .into_iter()
        .enumerate()
        .map(|(row_index, mut sidecar_data)| {
            for ith_bits in &converted_shares {
                sidecar_data.push(ith_bits[row_index].clone());
            }
            sidecar_data
        })
        .collect::<Vec<_>>();

    let sorted_rows = apply_sort_permutation(
        ctx.narrow(&Step::ApplySortPermutation),
        combined_match_keys_and_sidecar_data,
        &sort_permutation,
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

    let user_capped_credits = credit_capping(
        ctx.narrow(&Step::PerformUserCapping),
        &accumulated_credits,
        per_user_credit_cap,
    )
    .await?;

    aggregate_credit(ctx.narrow(&Step::AggregateCredit), &user_capped_credits, 3).await
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
        const PER_USER_CAP: u32 = 3;
        const EXPECTED: &[[u128; 2]] = &[[0, 0], [1, 2], [2, 3]];

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
                    ipa(ctx, &mk_shares, 20, shares_of_other_inputs, PER_USER_CAP)
                        .await
                        .unwrap()
                },
            )
            .await
            .reconstruct();

        assert_eq!(EXPECTED.len(), result.len());

        for (i, expected) in EXPECTED.iter().enumerate() {
            // Each element in the `result` is a general purpose `[F; 4]`.
            // For this test case, the first two elements are `breakdown_key`
            // and `credit` as defined by the implementation of `Reconstruct`
            // for `[AggregateCreditOutputRow<F>; 3]`.
            let result = result[i].0.map(|x| x.as_u128());
            assert_eq!(*expected, [result[0], result[1]]);
        }
    }
}
