use crate::{
    error::Error,
    ff::{Gf2, PrimeField, Serializable},
    protocol::{
        context::{UpgradableContext, UpgradedContext, Validator},
        modulus_conversion::convert_some_bits,
        sort::{check_everything, generate_permutation::ShuffledPermutationWrapper},
        step::BitOpStep,
        BasicProtocols, RecordId,
    },
    secret_sharing::{
        replicated::{
            malicious::{DowngradeMalicious, ExtendableField},
            semi_honest::AdditiveShare as Replicated,
        },
        BitDecomposed, Linear as LinearSecretSharing,
    },
    seq_join::seq_join,
};
use futures::stream::{iter as stream_iter, StreamExt, TryStreamExt};

/// This is the number of breakdown keys above which it is more efficient to SORT by breakdown key.
/// Below this number, it's more efficient to just do a ton of equality checks.
/// This number was determined empirically on 27 Feb 2023
const SIMPLE_AGGREGATION_BREAK_EVEN_POINT: u32 = 32;

/// Aggregation step for Oblivious Attribution protocol.
/// # Panics
/// It probably won't
///
/// # Errors
/// propagates errors from multiplications
#[tracing::instrument(name = "aggregate_credit", skip_all)]
// instrumenting this function makes the return type look bad to Clippy
#[allow(clippy::type_complexity)]
pub async fn aggregate_credit<C, V, F, IC, IB, S>(
    validator: V,
    breakdown_keys: IB,
    capped_credits: IC,
    max_breakdown_key: u32,
) -> Result<(V, Vec<S>), Error>
where
    C: UpgradableContext<Validator<F> = V>,
    C::UpgradedContext<F>: UpgradedContext<F, Share = S>,
    V: Validator<C, F>,
    F: PrimeField + ExtendableField,
    IB: IntoIterator<Item = BitDecomposed<Replicated<Gf2>>> + ExactSizeIterator + Send,
    IB::IntoIter: Send,
    IC: IntoIterator<Item = S> + ExactSizeIterator + Send,
    IC::IntoIter: Send,
    S: LinearSecretSharing<F> + BasicProtocols<C::UpgradedContext<F>, F> + Serializable + 'static,
    ShuffledPermutationWrapper<S, C::UpgradedContext<F>>: DowngradeMalicious<Target = Vec<u32>>,
{
    let m_ctx = validator.context();

    if max_breakdown_key <= SIMPLE_AGGREGATION_BREAK_EVEN_POINT {
        let res = simple_aggregate_credit(m_ctx, breakdown_keys, capped_credits, max_breakdown_key)
            .await?;
        Ok((validator, res))
    } else {
        Err(Error::Unsupported(
            format!("query uses {max_breakdown_key} breakdown keys; only {SIMPLE_AGGREGATION_BREAK_EVEN_POINT} are supported")
        ))
    }
}

async fn simple_aggregate_credit<F, C, IC, IB, S>(
    ctx: C,
    breakdown_keys: IB,
    capped_credits: IC,
    max_breakdown_key: u32,
) -> Result<Vec<S>, Error>
where
    F: PrimeField,
    IB: IntoIterator<Item = BitDecomposed<Replicated<Gf2>>> + ExactSizeIterator + Send,
    IB::IntoIter: Send,
    IC: IntoIterator<Item = S> + ExactSizeIterator + Send,
    IC::IntoIter: Send,
    C: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F> + BasicProtocols<C, F> + Serializable + 'static,
{
    assert_eq!(capped_credits.len(), breakdown_keys.len());
    let mut sums = vec![S::ZERO; max_breakdown_key as usize];
    let to_take = usize::try_from(max_breakdown_key).unwrap();
    let valid_bits_count = u32::BITS - (max_breakdown_key - 1).leading_zeros();

    let equality_check_context = ctx
        .narrow(&Step::ComputeEqualityChecks)
        .set_total_records(capped_credits.len());
    let check_times_credit_context = ctx
        .narrow(&Step::CheckTimesCredit)
        .set_total_records(capped_credits.len());

    let converted_bk = convert_some_bits(
        ctx.narrow(&Step::ModConvBreakdownKeyBits),
        stream_iter(breakdown_keys),
        0..valid_bits_count,
    );

    let increments = seq_join(
        ctx.active_work(),
        converted_bk
            .zip(stream_iter(capped_credits))
            .enumerate()
            .map(|(i, (bk, cred))| {
                let ceq = &equality_check_context;
                let cmul = &check_times_credit_context;
                async move {
                    let equality_checks = check_everything(ceq.clone(), i, &bk?).await?;
                    ceq.try_join(equality_checks.into_iter().take(to_take).enumerate().map(
                        |(check_idx, check)| {
                            let step = BitOpStep::from(check_idx);
                            let c = cmul.narrow(&step);
                            let record_id = RecordId::from(i);
                            let credit = &cred;
                            async move { check.multiply(credit, c, record_id).await }
                        },
                    ))
                    .await
                }
            }),
    )
    .try_collect::<Vec<_>>() // TODO: delay collection further
    .await?;

    for increments_for_row in increments {
        for (i, increment) in increments_for_row.iter().enumerate() {
            sums[i] += increment;
        }
    }
    Ok(sums)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Step {
    ComputeEqualityChecks,
    CheckTimesCredit,
    ModConvBreakdownKeyBits,
    UpgradeBits,
}

impl crate::protocol::step::Step for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::ComputeEqualityChecks => "compute_equality_checks",
            Self::CheckTimesCredit => "check_times_credit",
            Self::ModConvBreakdownKeyBits => "mod_conv_breakdown_key_bits",
            Self::UpgradeBits => "upgrade_breakdown_key_bits",
        }
    }
}

#[cfg(all(test, unit_test))]
mod tests {

    use super::aggregate_credit;
    use crate::{
        aggregation_test_input,
        ff::{Field, Fp32BitPrime, GaloisField, Gf2},
        protocol::{
            context::{Context, UpgradableContext, Validator},
            modulus_conversion::convert_some_bits,
            BreakdownKey, MatchKey,
        },
        secret_sharing::{
            replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed, SharedValue,
        },
        test_fixture::{input::GenericReportTestInput, Reconstruct, Runner, TestWorld},
    };
    use futures::stream::{iter as stream_iter, StreamExt, TryStreamExt};

    #[tokio::test]
    pub async fn aggregate() {
        const MAX_BREAKDOWN_KEY: u32 = 8;

        const EXPECTED: &[u128] = &[0, 0, 12, 0, 18, 6, 0, 0];

        // (breakdown_key, credit)
        const INPUT: &[(u32, u32)] = &[
            (3, 0),
            (4, 0),
            (4, 18),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
            (1, 0),
            (0, 0),
            (2, 2),
            (0, 0),
            (0, 0),
            (2, 0),
            (2, 10),
            (0, 0),
            (0, 0),
            (5, 6),
            (0, 0),
        ];

        let world = TestWorld::default();
        let result = world
            .semi_honest(
                INPUT.iter().map(|&(bk, credit)| {
                    (
                        // decomposed breakdown key
                        BitDecomposed::decompose(
                            u32::BITS - (MAX_BREAKDOWN_KEY - 1).leading_zeros(),
                            |i| Gf2::try_from((u128::from(bk) >> i) & 1).unwrap(),
                        ),
                        // credit
                        Fp32BitPrime::truncate_from(bk),
                    )
                }),
                |ctx, shares| async move {
                    let (bk_shares, credit_shares): (Vec<_>, Vec<_>) = shares.into_iter().unzip();
                    let validator = ctx.validator::<Fp32BitPrime>();
                    let u_ctx = validator.context();
                    let (_validator, output) = aggregate_credit(
                        ctx.clone().validator(), // note: not upgrading any inputs, so semi-honest only.
                        bk_shares.into_iter(),
                        credit_shares.into_iter(),
                        MAX_BREAKDOWN_KEY,
                    )
                    .await
                    .unwrap();
                    output
                },
            )
            .await
            .reconstruct();
        assert_eq!(result, EXPECTED);
    }
}
