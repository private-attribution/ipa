mod input;

use futures::{stream::iter as stream_iter, Stream, TryStreamExt};
use futures_util::StreamExt;
pub use input::SparseAggregateInputRow;

use super::{context::Context, sort::bitwise_to_onehot, step::BitOpStep, RecordId};
use crate::{
    error::Error,
    ff::{Field, GaloisField, Gf2, PrimeField, Serializable},
    protocol::{
        context::{UpgradableContext, UpgradedContext, Validator},
        modulus_conversion::convert_bits,
        BasicProtocols,
    },
    secret_sharing::{
        replicated::{
            malicious::{DowngradeMalicious, ExtendableField},
            semi_honest::AdditiveShare as Replicated,
            ReplicatedSecretSharing,
        },
        BitDecomposed, Linear as LinearSecretSharing, LinearRefOps,
    },
    seq_join::seq_join,
};

// TODO: Use `#[derive(Step)]` once the protocol is implemented and the bench test is enabled.
//       Once that is done, run `collect_steps.py` to generate `steps.txt` that includes these steps.

pub(crate) enum Step {
    Validator,
    ConvertValueBits,
    ConvertBreakdownKeyBits,
    ComputeEqualityChecks,
    CheckTimesValue,
}
impl crate::protocol::step::Step for Step {}
impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Step::Validator => "validator",
            Step::ConvertValueBits => "convert_value_bits",
            Step::ConvertBreakdownKeyBits => "convert_breakdown_key_bits",
            Step::ComputeEqualityChecks => "convert_equality_key_bits",
            Step::CheckTimesValue => "check_times_values",
        }
    }
}
#[cfg(feature = "compact-gate")]
impl super::step::StepNarrow<Step> for crate::protocol::step::Compact {
    fn narrow(&self, _step: &Step) -> Self {
        unimplemented!("compact gate is not supported in unit tests")
    }
}

/// Binary-share aggregation protocol for a sparse breakdown key vector input.
/// It takes a tuple of two vectors, `contribution_values` and `breakdown_keys`,
/// and aggregate each value to the corresponding histogram bucket specified by
/// the breakdown key. Since breakdown keys are secret shared, we need to create
/// a vector of Z2 shares for each record indicating which bucket the value
/// should be aggregated to. The output is a vector of Zp shares - a histogram
/// of the aggregated values.
///
/// # Errors
/// Propagates errors from multiplications
pub async fn sparse_aggregate<'a, C, S, SB, F, CV, BK>(
    sh_ctx: C,
    input_rows: &[SparseAggregateInputRow<CV, BK>],
    num_buckets: usize,
) -> Result<Vec<Replicated<F>>, Error>
where
    C: UpgradableContext,
    C::UpgradedContext<F>: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F>
        + BasicProtocols<C::UpgradedContext<F>, F>
        + Serializable
        + DowngradeMalicious<Target = Replicated<F>>
        + 'static,
    for<'r> &'r S: LinearRefOps<'r, S, F>,
    C::UpgradedContext<Gf2>: UpgradedContext<Gf2, Share = SB>,
    SB: LinearSecretSharing<Gf2> + BasicProtocols<C::UpgradedContext<Gf2>, Gf2> + 'static,
    F: PrimeField + ExtendableField,
    CV: GaloisField,
    BK: GaloisField,
{
    let validator = sh_ctx.narrow(&Step::Validator).validator::<F>();
    let ctx = validator.context().set_total_records(input_rows.len());
    let contributions = input_rows.iter().map(|row| &row.contribution_value);
    let breakdowns = input_rows.iter().map(|row| &row.breakdown_key);

    // convert the input from `[Z2]^u` into `[Zp]^u`
    let (converted_value_bits, converted_breakdown_key_bits) = (
        upgrade_bit_shares(
            &ctx.narrow(&Step::ConvertValueBits),
            contributions,
            CV::BITS,
        ),
        upgrade_bit_shares(
            &ctx.narrow(&Step::ConvertBreakdownKeyBits),
            breakdowns,
            BK::BITS,
        ),
    );

    let output = sparse_aggregate_values_per_bucket(
        ctx,
        converted_value_bits,
        converted_breakdown_key_bits,
        num_buckets,
    )
    .await?;

    validator.validate(output).await
}

/// This protocol assumes that devices and/or browsers have applied per-user
/// capping.
///
/// # Errors
/// propagates errors from multiplications
#[tracing::instrument(name = "aggregate_values_per_bucket", skip_all)]
pub async fn sparse_aggregate_values_per_bucket<F, I1, I2, C, S>(
    ctx: C,
    contribution_values: I1,
    breakdown_keys: I2,
    num_buckets: usize,
) -> Result<Vec<S>, Error>
where
    F: PrimeField,
    I1: Stream<Item = Result<BitDecomposed<S>, Error>> + Send,
    I2: Stream<Item = Result<BitDecomposed<S>, Error>> + Send,
    C: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F> + BasicProtocols<C, F> + Serializable + 'static,
    for<'a> &'a S: LinearRefOps<'a, S, F>,
{
    let equality_check_ctx = ctx.narrow(&Step::ComputeEqualityChecks);

    // Generate N streams for each bucket specified by the `num_buckets`.
    // A stream is pipeline of contribution values multiplied by the "equality bit". An equality
    // bit is a bit that is a share of 1 if the breakdown key matches the bucket, or 0 otherwise.
    let streams = seq_join(
        ctx.active_work(),
        breakdown_keys
            .zip(contribution_values)
            .enumerate()
            .map(|(i, (bk, v))| {
                let eq_ctx = &equality_check_ctx;
                let c = ctx.clone();
                async move {
                    let equality_checks = bitwise_to_onehot(eq_ctx.clone(), i, &bk?).await?;
                    equality_bits_times_value(&c, equality_checks, num_buckets, v?, i).await
                }
            }),
    );
    // for each bucket stream, sum up the contribution values
    streams
        .try_fold(vec![S::ZERO; num_buckets], |mut acc, bucket| async move {
            for (i, b) in bucket.into_iter().enumerate() {
                acc[i] += &b;
            }
            Ok(acc)
        })
        .await
}

async fn equality_bits_times_value<F, C, S>(
    ctx: &C,
    check_bits: BitDecomposed<S>,
    num_buckets: usize,
    value_bits: BitDecomposed<S>,
    record_id: usize,
) -> Result<Vec<S>, Error>
where
    F: PrimeField,
    C: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F> + BasicProtocols<C, F> + Serializable + 'static,
    for<'a> &'a S: LinearRefOps<'a, S, F>,
{
    let check_times_value_ctx = ctx.narrow(&Step::CheckTimesValue);

    ctx.try_join(
        check_bits
            .into_iter()
            .take(num_buckets)
            .enumerate()
            .map(|(check_idx, check)| {
                let step = BitOpStep::from(check_idx);
                let c = check_times_value_ctx.narrow(&step);
                let record_id = RecordId::from(record_id);
                let v = value_bits.to_additive_sharing_in_large_field();
                async move { check.multiply(&v, c, record_id).await }
            }),
    )
    .await
}

fn upgrade_bit_shares<'a, F, C, S, I, G>(
    ctx: &C,
    input_rows: I,
    num_bits: u32,
) -> impl Stream<Item = Result<BitDecomposed<S>, Error>> + 'a
where
    F: PrimeField,
    C: UpgradedContext<F, Share = S> + 'a,
    S: LinearSecretSharing<F> + BasicProtocols<C, F> + Serializable + 'static,
    I: Iterator<Item = &'a Replicated<G>> + Send + 'a,
    G: GaloisField,
{
    let gf2_bits = input_rows.map(move |row| {
        BitDecomposed::decompose(num_bits, |idx| {
            Replicated::new(
                Gf2::truncate_from(row.left()[idx]),
                Gf2::truncate_from(row.right()[idx]),
            )
        })
    });

    convert_bits(
        ctx.narrow(&Step::ConvertValueBits),
        stream_iter(gf2_bits),
        0..num_bits,
    )
}

#[cfg(all(test, unit_test))]
mod tests {
    use super::sparse_aggregate;
    use crate::{
        ff::{Field, Fp32BitPrime, GaloisField, Gf3Bit, Gf8Bit},
        protocol::aggregation::SparseAggregateInputRow,
        secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, SharedValue},
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    fn create_input_vec<BK, CV>(
        input: &[(Replicated<BK>, Replicated<CV>)],
    ) -> Vec<SparseAggregateInputRow<CV, BK>>
    where
        BK: GaloisField,
        CV: GaloisField,
    {
        input
            .iter()
            .map(|x| SparseAggregateInputRow {
                breakdown_key: x.0.clone(),
                contribution_value: x.1.clone(),
            })
            .collect::<Vec<_>>()
    }

    #[tokio::test]
    pub async fn aggregate() {
        type BK = Gf3Bit;
        type CV = Gf8Bit;

        const EXPECTED: &[u128] = &[28, 0, 0, 6, 1, 0, 0, 8];
        const NUM_BUCKETS: usize = 1 << BK::BITS;
        const INPUT: &[(u32, u32)] = &[
            // (breakdown_key, contribution_value)
            (0, 0),
            (0, 0),
            (0, 18),
            (0, 0),
            (0, 0),
            (3, 5),
            (0, 0),
            (4, 1),
            (0, 0),
            (0, 0),
            (7, 2),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 10),
            (3, 1),
            (0, 0),
            (7, 6),
            (0, 0),
        ];

        let bitwise_input = INPUT
            .iter()
            .map(|(bk, value)| (BK::truncate_from(*bk), CV::truncate_from(*value)));

        let world = TestWorld::default();
        let result = world
            .semi_honest(bitwise_input.clone(), |ctx, shares| async move {
                sparse_aggregate::<_, _, _, Fp32BitPrime, CV, BK>(
                    ctx,
                    &create_input_vec(&shares),
                    NUM_BUCKETS,
                )
                .await
                .unwrap()
            })
            .await
            .reconstruct();
        assert_eq!(result, EXPECTED);

        let result = world
            .malicious(bitwise_input.clone(), |ctx, shares| async move {
                sparse_aggregate::<_, _, _, Fp32BitPrime, CV, BK>(
                    ctx,
                    &create_input_vec(&shares),
                    NUM_BUCKETS,
                )
                .await
                .unwrap()
            })
            .await
            .reconstruct();
        assert_eq!(result, EXPECTED);
    }
}
