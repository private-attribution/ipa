mod input;

use futures::{future::try_join, stream::iter as stream_iter, TryStreamExt};
use futures_util::StreamExt;
pub use input::SparseAggregateInputRow;
use ipa_macros::step;
use strum::AsRefStr;

use super::{context::Context, sort::check_everything, step::BitOpStep, RecordId};
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
        BitDecomposed, Linear as LinearSecretSharing,
    },
    seq_join::seq_join,
};

#[step]
pub(crate) enum Step {
    Validator,
    ConvertValueBits,
    ConvertBreakdownKeyBits,
    ComputeEqualityChecks,
    CheckTimesValue,
}

/// Binary-share aggregation protocol for a sparse breakdown key vector input.
///
/// # Errors
/// Propagates errors from multiplications
pub async fn sparse_aggregate<'a, C, S, SB, F, CV, BK>(
    sh_ctx: C,
    input_rows: &[SparseAggregateInputRow<CV, BK>],
) -> Result<Vec<Replicated<F>>, Error>
where
    C: UpgradableContext,
    C::UpgradedContext<F>: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F>
        + BasicProtocols<C::UpgradedContext<F>, F>
        + Serializable
        + DowngradeMalicious<Target = Replicated<F>>
        + 'static,
    C::UpgradedContext<Gf2>: UpgradedContext<Gf2, Share = SB>,
    SB: LinearSecretSharing<Gf2> + BasicProtocols<C::UpgradedContext<Gf2>, Gf2> + 'static,
    F: PrimeField + ExtendableField,
    CV: GaloisField,
    BK: GaloisField,
{
    let validator = sh_ctx.narrow(&Step::Validator).validator::<F>();
    let ctx = validator.context();

    // convert the input from `[Z2]^u` into `[Zp]^u`
    let (converted_value_bits, converted_breakdown_key_bits) = try_join(
        upgrade_bit_shares(
            ctx.narrow(&Step::ConvertValueBits),
            input_rows,
            CV::BITS,
            |row, i| {
                Replicated::new(
                    Gf2::truncate_from(row.contribution_value.left()[i]),
                    Gf2::truncate_from(row.contribution_value.right()[i]),
                )
            },
        ),
        upgrade_bit_shares(
            ctx.narrow(&Step::ConvertBreakdownKeyBits),
            input_rows,
            BK::BITS,
            |row, i| {
                Replicated::new(
                    Gf2::truncate_from(row.breakdown_key.left()[i]),
                    Gf2::truncate_from(row.breakdown_key.right()[i]),
                )
            },
        ),
    )
    .await?;

    let output =
        aggregate_values_per_bucket(ctx, converted_value_bits, converted_breakdown_key_bits)
            .await?;

    validator.validate(output).await
}

/// This protocol assumes that devices and/or browsers have applied per-user
/// capping.
///
/// # Errors
/// propagates errors from multiplications
#[tracing::instrument(name = "aggregate_values_per_bucket", skip_all)]
pub async fn aggregate_values_per_bucket<F, C, S>(
    ctx: C,
    contribution_values: Vec<BitDecomposed<S>>,
    breakdown_keys: Vec<BitDecomposed<S>>,
) -> Result<Vec<S>, Error>
where
    F: PrimeField,
    C: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F> + BasicProtocols<C, F> + Serializable + 'static,
{
    debug_assert!(contribution_values.len() == breakdown_keys.len());
    let num_records = contribution_values.len();
    // for now, we assume that the bucket count is 2^BK::BITS
    let num_buckets = 1 << breakdown_keys[0].len();

    let equality_check_ctx = ctx
        .narrow(&Step::ComputeEqualityChecks)
        .set_total_records(num_records);

    // Generate N streams for each bucket specified by the breakdown key (N = |breakdown_keys|).
    // A stream is pipeline of contribution values multiplied by the "equality bit". An equality
    // bit is a bit that is a share of 1 if the breakdown key matches the bucket, or 0 otherwise.
    let streams = seq_join(
        ctx.active_work(),
        stream_iter(breakdown_keys)
            .zip(stream_iter(contribution_values))
            .enumerate()
            .map(|(i, (bk, v))| {
                let eq_ctx = &equality_check_ctx;
                let c = ctx.clone();
                async move {
                    let equality_checks = check_everything(eq_ctx.clone(), i, &bk).await?;
                    equality_bits_times_value(&c, equality_checks, num_buckets, v, num_records, i)
                        .await
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
    num_records: usize,
    record_id: usize,
) -> Result<Vec<S>, Error>
where
    F: PrimeField,
    C: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F> + BasicProtocols<C, F> + Serializable + 'static,
{
    let check_times_value_ctx = ctx
        .narrow(&Step::CheckTimesValue)
        .set_total_records(num_records);

    ctx.try_join(
        check_bits
            .into_iter()
            .take(num_buckets)
            .enumerate()
            .map(|(check_idx, check)| {
                let step = BitOpStep::from(check_idx);
                let c = check_times_value_ctx.narrow(&step);
                let record_id = RecordId::from(record_id);
                let v = &value_bits;
                async move {
                    check
                        .multiply(&v.to_additive_sharing_in_large_field(), c, record_id)
                        .await
                }
            }),
    )
    .await
}

async fn upgrade_bit_shares<F, C, S, H, CV, BK>(
    ctx: C,
    input_rows: &[SparseAggregateInputRow<CV, BK>],
    num_bits: u32,
    f: H,
) -> Result<Vec<BitDecomposed<S>>, Error>
where
    F: PrimeField,
    C: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F> + BasicProtocols<C, F> + Serializable + 'static,
    H: Fn(&SparseAggregateInputRow<CV, BK>, u32) -> Replicated<Gf2>,
    CV: GaloisField,
    BK: GaloisField,
{
    let num_records = input_rows.len();
    let gf2_bits = input_rows
        .iter()
        .map(|row| BitDecomposed::decompose(num_bits, |i| f(row, i)))
        .collect::<Vec<_>>();

    convert_bits(
        ctx.narrow(&Step::ConvertValueBits)
            .set_total_records(num_records),
        stream_iter(gf2_bits),
        0..num_bits,
    )
    .try_collect::<Vec<_>>()
    .await
}

#[cfg(all(test, unit_test))]
mod tests {
    use super::sparse_aggregate;
    use crate::{
        ff::{Field, Fp32BitPrime, GaloisField, Gf3Bit, Gf8Bit},
        protocol::aggregation::SparseAggregateInputRow,
        secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    fn create_input_vec<T, U>(
        input: &[(Replicated<T>, Replicated<U>)],
    ) -> Vec<SparseAggregateInputRow<T, U>>
    where
        T: GaloisField,
        U: GaloisField,
    {
        input
            .iter()
            .map(|x| SparseAggregateInputRow {
                contribution_value: x.0.clone(),
                breakdown_key: x.1.clone(),
            })
            .collect::<Vec<_>>()
    }

    #[tokio::test]
    pub async fn aggregate() {
        type CV = Gf8Bit;
        type BK = Gf3Bit;

        const EXPECTED: &[u128] = &[28, 0, 0, 6, 1, 0, 0, 8];

        const INPUT: &[(u32, u32)] = &[
            (0, 0),
            (0, 0),
            (18, 0),
            (0, 0),
            (0, 0),
            (5, 3),
            (0, 0),
            (1, 4),
            (0, 0),
            (0, 0),
            (2, 7),
            (0, 0),
            (0, 0),
            (0, 0),
            (10, 0),
            (1, 3),
            (0, 0),
            (6, 7),
            (0, 0),
        ];

        let bitwise_input = INPUT
            .iter()
            .map(|(value, bk)| (CV::truncate_from(*value), BK::truncate_from(*bk)));

        let world = TestWorld::default();
        let result = world
            .semi_honest(bitwise_input.clone(), |ctx, shares| async move {
                sparse_aggregate::<_, _, _, Fp32BitPrime, CV, BK>(ctx, &create_input_vec(&shares))
                    .await
                    .unwrap()
            })
            .await
            .reconstruct();
        assert_eq!(result, EXPECTED);

        let result = world
            .malicious(bitwise_input.clone(), |ctx, shares| async move {
                sparse_aggregate::<_, _, _, Fp32BitPrime, CV, BK>(ctx, &create_input_vec(&shares))
                    .await
                    .unwrap()
            })
            .await
            .reconstruct();
        assert_eq!(result, EXPECTED);
    }
}
