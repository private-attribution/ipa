mod input;

use futures::{stream::iter as stream_iter, TryStreamExt};
pub use input::SparseAggregateInputRow;

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
};

// TODO: Use `#[derive(Step)]` once the protocol is implemented and the bench test is enabled.
//       Once that is done, run `collect_steps.py` to generate `steps.txt` that includes these steps.

pub(crate) enum Step {
    Validator,
    ConvertValueBits,
}
impl crate::protocol::step::Step for Step {}
impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Step::Validator => "validator",
            Step::ConvertValueBits => "convert_value_bits",
        }
    }
}
#[cfg(feature = "compact-gate")]
impl super::step::StepNarrow<Step> for crate::protocol::step::Compact {
    fn narrow(&self, _step: &Step) -> Self {
        unimplemented!("compact gate is not supported in unit tests")
    }
}

/// Binary-share aggregation protocol.
///
/// # Errors
/// Propagates errors from multiplications
pub async fn aggregate<'a, C, S, SB, F, CV, BK>(
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

    let (gf2_value_bits, _gf2_breakdown_keys) = (
        get_gf2_value_bits(input_rows),
        get_gf2_breakdown_key_bits(input_rows),
    );

    // TODO(taikiy):
    // 1. slice the buckets into N streams and send them to the aggregation protocol
    // 2. collect the results and return them

    let output = aggregate_values(validator.context(), gf2_value_bits).await?;

    validator.validate(vec![output]).await
}

/// Performs a set of aggregation protocols on binary shared values.
/// This protocol assumes that devices and/or browsers have applied per-user
/// capping.
///
/// # Errors
/// propagates errors from multiplications
#[tracing::instrument(name = "simple_aggregate_values", skip_all)]
pub async fn aggregate_values<F, C, S>(
    ctx: C,
    contribution_value_bits_gf2: Vec<BitDecomposed<Replicated<Gf2>>>,
) -> Result<S, Error>
where
    F: PrimeField,
    C: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F> + BasicProtocols<C, F> + Serializable + 'static,
{
    let record_count = contribution_value_bits_gf2.len();
    let bits = contribution_value_bits_gf2[0].len();

    // mod-convert for later validation
    let convert_ctx = ctx
        .narrow(&Step::ConvertValueBits)
        .set_total_records(record_count);
    let converted_contribution_values = convert_bits(
        convert_ctx,
        stream_iter(contribution_value_bits_gf2),
        0..u32::try_from(bits).unwrap(),
    );

    let aggregate = converted_contribution_values
        .try_fold(S::ZERO, |mut acc, row| async move {
            acc += &row.to_additive_sharing_in_large_field();
            Ok(acc)
        })
        .await?;

    Ok(aggregate)
}

fn get_gf2_value_bits<CV, BK>(
    input_rows: &[SparseAggregateInputRow<CV, BK>],
) -> Vec<BitDecomposed<Replicated<Gf2>>>
where
    CV: GaloisField,
    BK: GaloisField,
{
    input_rows
        .iter()
        .map(|row| {
            BitDecomposed::decompose(CV::BITS, |i| {
                Replicated::new(
                    Gf2::truncate_from(row.contribution_value.left()[i]),
                    Gf2::truncate_from(row.contribution_value.right()[i]),
                )
            })
        })
        .collect::<Vec<_>>()
}

fn get_gf2_breakdown_key_bits<CV, BK>(
    input_rows: &[SparseAggregateInputRow<CV, BK>],
) -> Vec<BitDecomposed<Replicated<Gf2>>>
where
    CV: GaloisField,
    BK: GaloisField,
{
    input_rows
        .iter()
        .map(|row| {
            BitDecomposed::decompose(BK::BITS, |i| {
                Replicated::new(
                    Gf2::truncate_from(row.breakdown_key.left()[i]),
                    Gf2::truncate_from(row.breakdown_key.right()[i]),
                )
            })
        })
        .collect::<Vec<_>>()
}

#[cfg(all(test, unit_test))]
mod tests {
    use super::aggregate_values;
    use crate::{
        ff::{Fp32BitPrime, Gf2},
        protocol::context::{UpgradableContext, Validator},
        secret_sharing::BitDecomposed,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn aggregate() {
        const CONTRIBUTION_BITS: u32 = 8;
        const EXPECTED: u128 = 36;

        const INPUT: &[u32] = &[0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 10, 0, 0, 6, 0];

        let world = TestWorld::default();
        let result = world
            .semi_honest(
                INPUT.iter().map(|&value| {
                    BitDecomposed::decompose(CONTRIBUTION_BITS, |i| {
                        Gf2::try_from((u128::from(value) >> i) & 1).unwrap()
                    })
                }),
                |ctx, shares| async move {
                    let validator = ctx.validator::<Fp32BitPrime>();
                    aggregate_values(
                        validator.context(), // note: not upgrading any inputs, so semi-honest only.
                        shares,
                    )
                    .await
                    .unwrap()
                },
            )
            .await
            .reconstruct();
        assert_eq!(result, EXPECTED);
    }

    //TODO(taikiy): add malicious test
}
