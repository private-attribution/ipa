mod input;
use std::iter::zip;

use futures::future::try_join;
pub use input::AggregateInputRow;
use ipa_macros::step;
use strum::AsRefStr;

use self::input::BinarySharedAggregateInputs;
use crate::{
    error::Error,
    ff::{Field, GaloisField, Gf2, PrimeField},
    protocol::{
        context::{Context, UpgradableContext, UpgradedContext, Validator},
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

#[step]
pub(crate) enum Step {
    BinaryValidator,
    UpgradeValueBits,
    UpgradeBreakdownKeyBits,
}

/// Binary-share aggregation protocol.
///
/// # Errors
/// Propagates errors from multiplications
pub async fn aggregate<'a, C, SB, F, V, BK>(
    sh_ctx: C,
    input_rows: &[AggregateInputRow<V, BK>],
) -> Result<Vec<Replicated<F>>, Error>
where
    C: UpgradableContext,
    C::UpgradedContext<Gf2>: UpgradedContext<Gf2, Share = SB>,
    SB: LinearSecretSharing<Gf2>
        + BasicProtocols<C::UpgradedContext<Gf2>, Gf2>
        + DowngradeMalicious<Target = Replicated<Gf2>>
        + 'static,
    F: PrimeField + ExtendableField,
    V: GaloisField,
    BK: GaloisField,
{
    let validator = sh_ctx.narrow(&Step::BinaryValidator).validator();
    let m_ctx = validator.context();

    let (gf2_value_bits, gf2_breakdown_keys) = (
        get_gf2_value_bits(input_rows),
        get_gf2_breakdown_key_bits(input_rows),
    );
    let (upgraded_gf2_value_bits, upgraded_gf2_breakdown_key_bits) = try_join(
        m_ctx
            .narrow(&Step::UpgradeValueBits)
            .upgrade(gf2_value_bits),
        m_ctx
            .narrow(&Step::UpgradeBreakdownKeyBits)
            .upgrade(gf2_breakdown_keys),
    )
    .await?;
    let binary_shared_values = zip(upgraded_gf2_value_bits, upgraded_gf2_breakdown_key_bits)
        .map(|(value, breakdown_key)| BinarySharedAggregateInputs::new(value, breakdown_key))
        .collect::<Vec<_>>();

    secure_aggregation(validator, binary_shared_values).await
}

/// Performs a set of aggregation protocols on binary shared values.
///
/// # Errors
/// propagates errors from multiplications
#[tracing::instrument(name = "aggregate", skip_all)]
pub async fn secure_aggregation<V, VB, C, SB, F>(
    _binary_validator: VB,
    _binary_shared_values: Vec<BinarySharedAggregateInputs<SB>>,
) -> Result<Vec<Replicated<F>>, Error>
where
    VB: Validator<C, Gf2>,
    C: UpgradableContext<Validator<F> = V>,
    C::UpgradedContext<Gf2>: UpgradedContext<Gf2, Share = SB> + Context,
    SB: LinearSecretSharing<Gf2>
        + BasicProtocols<C::UpgradedContext<Gf2>, Gf2>
        + DowngradeMalicious<Target = Replicated<Gf2>>
        + 'static,
    F: PrimeField + ExtendableField,
{
    // TODO(taikiy):
    // 0. This protocol assumes that the input rows are from the same match key
    //    so that we don't have to worry about computing the helper_bits. There
    //    will be some pre-processing to do before this protocol is called.
    // 1. validate the binary shares
    // 2. mod convert
    // 3. apply capping
    // 4. aggregate per breakdown key
    // 5. validate the result before returning

    todo!()
}

fn get_gf2_value_bits<V, BK>(
    input_rows: &[AggregateInputRow<V, BK>],
) -> Vec<BitDecomposed<Replicated<Gf2>>>
where
    V: GaloisField,
    BK: GaloisField,
{
    input_rows
        .iter()
        .map(|row| {
            BitDecomposed::decompose(V::BITS, |i| {
                Replicated::new(
                    Gf2::truncate_from(row.value.left()[i]),
                    Gf2::truncate_from(row.value.right()[i]),
                )
            })
        })
        .collect::<Vec<_>>()
}

fn get_gf2_breakdown_key_bits<V, BK>(
    input_rows: &[AggregateInputRow<V, BK>],
) -> Vec<BitDecomposed<Replicated<Gf2>>>
where
    V: GaloisField,
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
