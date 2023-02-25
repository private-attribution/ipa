use crate::{
    bits::{Fp2Array, Serializable},
    error::Error,
    ff::Field,
    protocol::{
        attribution::{
            do_the_binary_tree_thing,
            input::{
                MCAggregateCreditInputRow, MCAggregateCreditOutputRow,
                MCCappedCreditsWithAggregationBit,
            },
        },
        context::{Context, MaliciousContext, SemiHonestContext},
        malicious::MaliciousValidator,
        modulus_conversion::split_into_multi_bit_slices,
        sort::{
            apply_sort::apply_sort_permutation,
            generate_permutation::{
                generate_permutation_and_reveal_shuffled,
                malicious_generate_permutation_and_reveal_shuffled,
            },
        },
        BasicProtocols, Substep,
    },
    secret_sharing::{
        replicated::{
            malicious::AdditiveShare as MaliciousReplicated,
            semi_honest::AdditiveShare as Replicated,
        },
        Arithmetic,
    },
};

use crate::protocol::ipa::Step::AggregateCredit;

/// Aggregation step for Oblivious Attribution protocol.
/// # Panics
/// It probably won't
///
/// # Errors
/// propagates errors from multiplications
pub async fn aggregate_credit<F, BK>(
    ctx: SemiHonestContext<'_>,
    capped_credits: &[MCAggregateCreditInputRow<F, Replicated<F>>],
    max_breakdown_key: u128,
    num_multi_bits: u32,
) -> Result<Vec<MCAggregateCreditOutputRow<F, Replicated<F>, BK>>, Error>
where
    F: Field,
    BK: Fp2Array,
    for<'a> Replicated<F>: Serializable + BasicProtocols<SemiHonestContext<'a>, F>,
{
    //
    // 1. Add aggregation bits and new rows per unique breakdown_key
    //
    let capped_credits_with_aggregation_bits = add_aggregation_bits_and_breakdown_keys::<_, _, _, BK>(
        &ctx,
        capped_credits,
        max_breakdown_key,
    );

    //
    // 2. Sort by `breakdown_key`. Rows with `aggregation_bit` = 0 must
    // precede all other rows in the input. (done in the previous step).
    //
    let sorted_input = sort_by_breakdown_key(
        ctx.narrow(&Step::SortByBreakdownKey),
        capped_credits_with_aggregation_bits,
        max_breakdown_key,
        num_multi_bits,
    )
    .await?;

    //
    // 3. Aggregate by parallel prefix sum of credits per breakdown_key
    //
    //     b = current.stop_bit * successor.helper_bit;
    //     new_credit[current_index] = current.credit + b * successor.credit;
    //     new_stop_bit[current_index] = b * successor.stop_bit;
    //
    let helper_bits = sorted_input
        .iter()
        .skip(1)
        .map(|x| x.helper_bit.clone())
        .collect::<Vec<_>>();

    let mut credits = sorted_input
        .iter()
        .map(|x| x.credit.clone())
        .collect::<Vec<_>>();

    do_the_binary_tree_thing(ctx.clone(), helper_bits, &mut credits).await?;

    // Prepare the sidecar for sorting
    let aggregated_credits = sorted_input
        .iter()
        .enumerate()
        .map(|(i, x)| {
            MCCappedCreditsWithAggregationBit::new(
                x.helper_bit.clone(),
                x.aggregation_bit.clone(),
                x.breakdown_key.clone(),
                credits[i].clone(),
            )
        })
        .collect::<Vec<_>>();

    //
    // 4. Sort by `aggregation_bit`
    //
    let sorted_output =
        sort_by_aggregation_bit(ctx.narrow(&Step::SortByAttributionBit), aggregated_credits)
            .await?;

    // Take the first k elements, where k is the amount of breakdown keys.
    Ok(sorted_output
        .iter()
        .take(max_breakdown_key.try_into().unwrap())
        .map(|x| MCAggregateCreditOutputRow::new(x.breakdown_key.clone(), x.credit.clone()))
        .collect::<Vec<_>>())
}

/// Aggregation step for Oblivious Attribution protocol.
/// # Panics
/// It probably won't
///
/// # Errors
/// propagates errors from multiplications
pub async fn malicious_aggregate_credit<'a, F, BK>(
    malicious_validator: MaliciousValidator<'a, F>,
    sh_ctx: SemiHonestContext<'a>,
    capped_credits: &[MCAggregateCreditInputRow<F, MaliciousReplicated<F>>],
    max_breakdown_key: u128,
    num_multi_bits: u32,
) -> Result<
    (
        MaliciousValidator<'a, F>,
        Vec<MCAggregateCreditOutputRow<F, MaliciousReplicated<F>, BK>>,
    ),
    Error,
>
where
    F: Field,
    BK: Fp2Array,
    MaliciousReplicated<F>: Serializable + BasicProtocols<MaliciousContext<'a, F>, F>,
{
    let m_ctx = malicious_validator.context().narrow(&AggregateCredit);
    //
    // 1. Add aggregation bits and new rows per unique breakdown_key
    //
    let capped_credits_with_aggregation_bits = add_aggregation_bits_and_breakdown_keys::<_, _, _, BK>(
        &m_ctx,
        capped_credits,
        max_breakdown_key,
    );

    let capped_credits_with_aggregation_bits = malicious_validator
        .validate(capped_credits_with_aggregation_bits)
        .await?;
    //
    // 2. Sort by `breakdown_key`. Rows with `aggregation_bit` = 0 must
    // precede all other rows in the input. (done in the previous step).
    //
    let (malicious_validator, sorted_input) = malicious_sort_by_breakdown_key(
        sh_ctx.narrow(&Step::SortByBreakdownKey),
        capped_credits_with_aggregation_bits,
        max_breakdown_key,
        num_multi_bits,
    )
    .await?;

    let m_ctx = malicious_validator.context();
    //
    // 3. Aggregate by parallel prefix sum of credits per breakdown_key
    //
    //     b = current.stop_bit * successor.helper_bit;
    //     new_credit[current_index] = current.credit + b * successor.credit;
    //     new_stop_bit[current_index] = b * successor.stop_bit;
    //
    let helper_bits = sorted_input
        .iter()
        .skip(1)
        .map(|x| x.helper_bit.clone())
        .collect::<Vec<_>>();

    let mut credits = sorted_input
        .iter()
        .map(|x| x.credit.clone())
        .collect::<Vec<_>>();

    do_the_binary_tree_thing(m_ctx, helper_bits, &mut credits).await?;

    // Prepare the sidecar for sorting
    let aggregated_credits = sorted_input
        .iter()
        .enumerate()
        .map(|(i, x)| {
            MCCappedCreditsWithAggregationBit::new(
                x.helper_bit.clone(),
                x.aggregation_bit.clone(),
                x.breakdown_key.clone(),
                credits[i].clone(),
            )
        })
        .collect::<Vec<_>>();

    let aggregated_credits = malicious_validator.validate(aggregated_credits).await?;
    //
    // 4. Sort by `aggregation_bit`
    //
    let (malicious_validator, sorted_output) = malicious_sort_by_aggregation_bit(
        sh_ctx.narrow(&Step::SortByAttributionBit),
        aggregated_credits,
    )
    .await?;

    // Take the first k elements, where k is the amount of breakdown keys.
    let result = sorted_output
        .iter()
        .take(max_breakdown_key.try_into().unwrap())
        .map(|x| MCAggregateCreditOutputRow::new(x.breakdown_key.clone(), x.credit.clone()))
        .collect::<Vec<_>>();

    Ok((malicious_validator, result))
}

fn add_aggregation_bits_and_breakdown_keys<F, C, T, BK>(
    ctx: &C,
    capped_credits: &[MCAggregateCreditInputRow<F, T>],
    max_breakdown_key: u128,
) -> Vec<MCCappedCreditsWithAggregationBit<F, T>>
where
    F: Field,
    C: Context,
    T: Arithmetic<F> + BasicProtocols<C, F>,
    BK: Fp2Array,
{
    let zero = T::ZERO;
    let one = T::share_known_value(ctx, F::ONE);

    // Unique breakdown_key values with all other fields initialized with 0's.
    // Since we cannot see the actual breakdown key values, we'll need to
    // append all possible values. For now, we assume breakdown_key is in the
    // range of (0..max_breakdown_key).
    let mut unique_breakdown_keys = (0..max_breakdown_key)
        .map(|i| {
            // Since these breakdown keys are publicly known, we can directly convert them to Vec<Replicated<F>>
            let bk_bits = BK::truncate_from(i);
            let converted_bk = (0..BK::BITS)
                .map(|i| {
                    if bk_bits[i] {
                        one.clone()
                    } else {
                        zero.clone()
                    }
                })
                .collect::<Vec<_>>();

            MCCappedCreditsWithAggregationBit::new(
                zero.clone(),
                zero.clone(),
                converted_bk,
                zero.clone(),
            )
        })
        .collect::<Vec<_>>();

    // Add aggregation bits and initialize with 1's.
    unique_breakdown_keys.append(
        &mut capped_credits
            .iter()
            .map(|x| {
                MCCappedCreditsWithAggregationBit::new(
                    one.clone(),
                    one.clone(),
                    x.breakdown_key.clone(),
                    x.credit.clone(),
                )
            })
            .collect::<Vec<_>>(),
    );

    unique_breakdown_keys
}

async fn sort_by_breakdown_key<F: Field>(
    ctx: SemiHonestContext<'_>,
    input: Vec<MCCappedCreditsWithAggregationBit<F, Replicated<F>>>,
    max_breakdown_key: u128,
    num_multi_bits: u32,
) -> Result<Vec<MCCappedCreditsWithAggregationBit<F, Replicated<F>>>, Error> {
    let breakdown_keys = input
        .iter()
        .map(|x| x.breakdown_key.clone())
        .collect::<Vec<_>>();

    // We only need to run a radix sort on the bits used by all possible
    // breakdown key values.
    let valid_bits_count = u128::BITS - (max_breakdown_key - 1).leading_zeros();

    let breakdown_keys =
        split_into_multi_bit_slices(&breakdown_keys, valid_bits_count, num_multi_bits);

    let sort_permutation = generate_permutation_and_reveal_shuffled(
        ctx.narrow(&Step::GeneratePermutationByBreakdownKey),
        breakdown_keys.iter(),
    )
    .await?;

    apply_sort_permutation(
        ctx.narrow(&Step::ApplyPermutationOnBreakdownKey),
        input,
        &sort_permutation,
    )
    .await
}

async fn malicious_sort_by_breakdown_key<F: Field>(
    ctx: SemiHonestContext<'_>,
    input: Vec<MCCappedCreditsWithAggregationBit<F, Replicated<F>>>,
    max_breakdown_key: u128,
    num_multi_bits: u32,
) -> Result<
    (
        MaliciousValidator<'_, F>,
        Vec<MCCappedCreditsWithAggregationBit<F, MaliciousReplicated<F>>>,
    ),
    Error,
> {
    let breakdown_keys = input
        .iter()
        .map(|x| x.breakdown_key.clone())
        .collect::<Vec<_>>();

    // We only need to run a radix sort on the bits used by all possible
    // breakdown key values.
    let valid_bits_count = u128::BITS - (max_breakdown_key - 1).leading_zeros();

    let breakdown_keys =
        split_into_multi_bit_slices(&breakdown_keys, valid_bits_count, num_multi_bits);

    let sort_permutation = malicious_generate_permutation_and_reveal_shuffled(
        ctx.narrow(&Step::GeneratePermutationByBreakdownKey),
        breakdown_keys.iter(),
    )
    .await?;

    let malicious_validator = MaliciousValidator::new(ctx);
    let m_ctx = malicious_validator.context();
    let input = m_ctx.upgrade(input).await?;
    Ok((
        malicious_validator,
        apply_sort_permutation(
            m_ctx.narrow(&Step::ApplyPermutationOnBreakdownKey),
            input,
            &sort_permutation,
        )
        .await?,
    ))
}

async fn sort_by_aggregation_bit<F: Field>(
    ctx: SemiHonestContext<'_>,
    input: Vec<MCCappedCreditsWithAggregationBit<F, Replicated<F>>>,
) -> Result<Vec<MCCappedCreditsWithAggregationBit<F, Replicated<F>>>, Error> {
    // Since aggregation_bit is a 1-bit share of 1 or 0, we'll just extract the
    // field and wrap it in another vector.
    let aggregation_bits = [input
        .iter()
        .map(|x| vec![x.aggregation_bit.clone()])
        .collect::<Vec<_>>()];

    let sort_permutation = generate_permutation_and_reveal_shuffled(
        ctx.narrow(&Step::GeneratePermutationByAttributionBit),
        aggregation_bits.iter(),
    )
    .await?;

    apply_sort_permutation(
        ctx.narrow(&Step::ApplyPermutationOnAttributionBit),
        input,
        &sort_permutation,
    )
    .await
}

async fn malicious_sort_by_aggregation_bit<'a, F: Field>(
    ctx: SemiHonestContext<'_>,
    input: Vec<MCCappedCreditsWithAggregationBit<F, Replicated<F>>>,
) -> Result<
    (
        MaliciousValidator<'_, F>,
        Vec<MCCappedCreditsWithAggregationBit<F, MaliciousReplicated<F>>>,
    ),
    Error,
> {
    // Since aggregation_bit is a 1-bit share of 1 or 0, we'll just extract the
    // field and wrap it in another vector.
    let aggregation_bits = [input
        .iter()
        .map(|x| vec![x.aggregation_bit.clone()])
        .collect::<Vec<_>>()];

    let sort_permutation = malicious_generate_permutation_and_reveal_shuffled(
        ctx.narrow(&Step::GeneratePermutationByAttributionBit),
        aggregation_bits.iter(),
    )
    .await?;

    let malicious_validator = MaliciousValidator::new(ctx);
    let m_ctx = malicious_validator.context();
    let input = m_ctx.upgrade(input).await?;

    Ok((
        malicious_validator,
        apply_sort_permutation(
            m_ctx.narrow(&Step::ApplyPermutationOnAttributionBit),
            input,
            &sort_permutation,
        )
        .await?,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    SortByBreakdownKey,
    SortByAttributionBit,
    GeneratePermutationByBreakdownKey,
    ApplyPermutationOnBreakdownKey,
    GeneratePermutationByAttributionBit,
    ApplyPermutationOnAttributionBit,
}

impl Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::SortByBreakdownKey => "sort_by_breakdown_key",
            Self::SortByAttributionBit => "sort_by_attribution_bit",
            Self::GeneratePermutationByBreakdownKey => "generate_permutation_by_breakdown_key",
            Self::ApplyPermutationOnBreakdownKey => "apply_permutation_by_breakdown_key",
            Self::GeneratePermutationByAttributionBit => "generate_permutation_by_attribution_bit",
            Self::ApplyPermutationOnAttributionBit => "apply_permutation_on_attribution_bit",
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {

    use super::aggregate_credit;
    use crate::{
        aggregation_test_input,
        bits::Fp2Array,
        ff::{Field, Fp32BitPrime},
        protocol::{
            attribution::input::{AggregateCreditInputRow, MCAggregateCreditInputRow},
            context::Context,
            modulus_conversion::{convert_all_bits, convert_all_bits_local},
            BreakdownKey, MatchKey,
        },
        secret_sharing::SharedValue,
        test_fixture::{input::GenericReportTestInput, Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn aggregate() {
        const MAX_BREAKDOWN_KEY: u128 = 8;
        const NUM_MULTI_BITS: u32 = 3;

        const EXPECTED: &[[u128; 2]] = &[
            // breakdown_key, credit
            [0, 0],
            [1, 0],
            [2, 12],
            [3, 0],
            [4, 18],
            [5, 6],
            [6, 0],
            [7, 0],
        ];

        let input: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = aggregation_test_input!(
            [
                { helper_bit: 0, breakdown_key: 3, credit: 0 },
                { helper_bit: 0, breakdown_key: 4, credit: 0 },
                { helper_bit: 1, breakdown_key: 4, credit: 18 },
                { helper_bit: 1, breakdown_key: 0, credit: 0 },
                { helper_bit: 1, breakdown_key: 0, credit: 0 },
                { helper_bit: 1, breakdown_key: 0, credit: 0 },
                { helper_bit: 1, breakdown_key: 0, credit: 0 },
                { helper_bit: 1, breakdown_key: 0, credit: 0 },
                { helper_bit: 0, breakdown_key: 1, credit: 0 },
                { helper_bit: 0, breakdown_key: 0, credit: 0 },
                { helper_bit: 0, breakdown_key: 2, credit: 2 },
                { helper_bit: 1, breakdown_key: 0, credit: 0 },
                { helper_bit: 1, breakdown_key: 0, credit: 0 },
                { helper_bit: 1, breakdown_key: 2, credit: 0 },
                { helper_bit: 1, breakdown_key: 2, credit: 10 },
                { helper_bit: 1, breakdown_key: 0, credit: 0 },
                { helper_bit: 1, breakdown_key: 0, credit: 0 },
                { helper_bit: 1, breakdown_key: 5, credit: 6 },
                { helper_bit: 1, breakdown_key: 0, credit: 0 },
            ];
            (Fp32BitPrime, MatchKey, BreakdownKey)
        );

        let world = TestWorld::new().await;
        let result: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = world
            .semi_honest(
                input,
                |ctx, input: Vec<AggregateCreditInputRow<Fp32BitPrime, BreakdownKey>>| async move {
                    let bk_shares = input
                        .iter()
                        .map(|x| x.breakdown_key.clone())
                        .collect::<Vec<_>>();
                    let mut converted_bk_shares = convert_all_bits(
                        ctx.clone(),
                        &convert_all_bits_local(ctx.role(), &bk_shares),
                        BreakdownKey::BITS,
                        BreakdownKey::BITS,
                    )
                    .await
                    .unwrap();
                    let converted_bk_shares = converted_bk_shares.pop().unwrap();
                    let modulus_converted_shares: Vec<_> = input
                        .iter()
                        .zip(converted_bk_shares)
                        .map(|(row, bk)| MCAggregateCreditInputRow::new(bk, row.credit.clone()))
                        .collect();

                    aggregate_credit::<Fp32BitPrime, BreakdownKey>(
                        ctx,
                        &modulus_converted_shares,
                        MAX_BREAKDOWN_KEY,
                        NUM_MULTI_BITS,
                    )
                    .await
                    .unwrap()
                },
            )
            .await
            .reconstruct();

        for (i, expected) in EXPECTED.iter().enumerate() {
            assert_eq!(
                *expected,
                [
                    result[i].breakdown_key.as_u128(),
                    result[i].trigger_value.as_u128()
                ]
            );
        }
    }
}
