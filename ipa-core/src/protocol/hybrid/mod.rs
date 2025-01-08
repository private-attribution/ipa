pub(crate) mod agg;
pub(crate) mod breakdown_reveal;
pub(crate) mod oprf;
pub(crate) mod step;

use std::{convert::Infallible, ops::Add};

use generic_array::ArrayLength;
use tracing::{info_span, Instrument};

use crate::{
    error::{Error, LengthError},
    ff::{
        boolean::Boolean, boolean_array::BooleanArray, curve_points::RP25519,
        ec_prime_field::Fp25519, Serializable, U128Conversions,
    },
    helpers::query::DpMechanism,
    protocol::{
        basics::{
            shard_fin::{FinalizerContext, Histogram},
            BooleanArrayMul, Reveal,
        },
        context::{
            DZKPUpgraded, MacUpgraded, MaliciousProtocolSteps, ShardedContext, UpgradableContext,
        },
        dp::dp_for_histogram,
        hybrid::{
            agg::aggregate_reports,
            breakdown_reveal::breakdown_reveal_aggregation,
            oprf::{compute_prf_and_reshard, BreakdownKey, CONV_CHUNK, PRF_CHUNK},
            step::{FinalizeSteps, HybridStep as Step},
        },
        ipa_prf::{
            oprf_padding::{apply_dp_padding, PaddingParameters},
            prf_eval::PrfSharing,
            shuffle::ShardedShuffle,
        },
        prss::FromPrss,
        BooleanProtocols,
    },
    report::hybrid::{IndistinguishableHybridReport, PrfHybridReport},
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed, FieldSimd,
        TransposeFrom, Vectorizable,
    },
};

/// The Hybrid Protocol
///
/// This protocol takes in a [`Vec<IndistinguishableHybridReport<BK, V>>`]
/// and aggregates it into a summary report. `HybridReport`s are either
/// impressions or conversion. The protocol joins these based on their matchkeys,
/// sums the values from conversions grouped by the breakdown key on impressions.
/// To accomplish this, hte protocol performs the follwoing steps
/// 1. Generates a random number of "dummy records" (needed to mask the information that will
///    be revealed in step 4, and thereby provide a differential privacy guarantee on
///    that information leakage)
/// 2. Shuffles the input
/// 3. Computes an OPRF of these elliptic curve points and reveals this "pseudonym"
/// 4. Groups together rows with the same OPRF and sums both the breakdown keys and values.
/// 5. Generates a random number of "dummy records" (needed to mask the information that will
///    be revealed in step 7)
/// 6. Shuffles the input
/// 7. Reveals breakdown keys
/// 8. Sums the values by breakdown keys
/// 9. Adds random noise to the total value for each breakdown key (to provide a
///    differential privacy guarantee)
///
/// # Errors
/// Propagates errors from config issues or while running the protocol
/// # Panics
/// Propagates errors from config issues or while running the protocol
pub async fn hybrid_protocol<'ctx, C, BK, V, HV, const SS_BITS: usize, const B: usize>(
    ctx: C,
    input_rows: Vec<IndistinguishableHybridReport<BK, V>>,
    dp_params: DpMechanism,
    dp_padding_params: PaddingParameters,
) -> Result<Vec<Replicated<HV>>, Error>
where
    C: UpgradableContext
        + 'ctx
        + ShardedShuffle
        + ShardedContext
        + FinalizerContext<FinalizingContext = DZKPUpgraded<C>>,
    BK: BreakdownKey<B>,
    V: BooleanArray + U128Conversions,
    HV: BooleanArray + U128Conversions,
    <HV as Serializable>::Size: Add<<HV as Serializable>::Size, Output: ArrayLength>,
    Boolean: FieldSimd<B>,
    Replicated<Boolean, CONV_CHUNK>: BooleanProtocols<DZKPUpgraded<C>, CONV_CHUNK>,
    Replicated<Fp25519, PRF_CHUNK>:
        PrfSharing<MacUpgraded<C, Fp25519>, PRF_CHUNK, Field = Fp25519> + FromPrss,
    Replicated<RP25519, PRF_CHUNK>:
        Reveal<MacUpgraded<C, Fp25519>, Output = <RP25519 as Vectorizable<PRF_CHUNK>>::Array>,
    PrfHybridReport<BK, V>: Serializable,
    Replicated<Boolean>: BooleanProtocols<DZKPUpgraded<C>>,
    Replicated<Boolean, B>: BooleanProtocols<DZKPUpgraded<C>, B>,
    Replicated<BK>: BooleanArrayMul<DZKPUpgraded<C>>
        + Reveal<DZKPUpgraded<C>, Output = <BK as Vectorizable<1>>::Array>,
    BitDecomposed<Replicated<Boolean, B>>:
        for<'a> TransposeFrom<&'a [Replicated<V>; B], Error = Infallible>,
    BitDecomposed<Replicated<Boolean, B>>:
        for<'a> TransposeFrom<&'a [Replicated<HV>; B], Error = Infallible>,
    BitDecomposed<Replicated<Boolean, B>>:
        for<'a> TransposeFrom<&'a Vec<Replicated<HV>>, Error = LengthError>,
    Vec<Replicated<HV>>:
        for<'a> TransposeFrom<&'a BitDecomposed<Replicated<Boolean, B>>, Error = LengthError>,
    DZKPUpgraded<C>: ShardedContext,
{
    if input_rows.is_empty() {
        return Ok(vec![Replicated::ZERO; B]);
    }

    // Apply DP padding for OPRF
    let padded_input_rows = apply_dp_padding::<_, IndistinguishableHybridReport<BK, V>, B>(
        ctx.narrow(&Step::PaddingDp),
        input_rows,
        &dp_padding_params,
    )
    .await?;

    let shuffled_input_rows = ctx
        .narrow(&Step::InputShuffle)
        .sharded_shuffle(padded_input_rows)
        .instrument(info_span!("shuffle_inputs"))
        .await?;

    let sharded_reports = compute_prf_and_reshard(ctx.clone(), shuffled_input_rows).await?;

    let aggregated_reports = aggregate_reports::<BK, V, C>(ctx.clone(), sharded_reports).await?;

    let histogram = breakdown_reveal_aggregation::<C, BK, V, HV, B>(
        ctx.narrow(&Step::Aggregate),
        aggregated_reports,
        &dp_padding_params,
    )
    .await?;

    let histogram: Histogram<HV, B> = Histogram::from(histogram);

    let finalized_histogram = ctx
        .narrow(&Step::Finalize)
        .finalize(
            MaliciousProtocolSteps {
                protocol: &FinalizeSteps::Add,
                validate: &FinalizeSteps::Validate,
            },
            histogram,
        )
        .await?;

    let noisy_histogram = if ctx.is_leader() {
        dp_for_histogram::<_, B, HV, SS_BITS>(ctx, finalized_histogram.values, dp_params).await?
    } else {
        finalized_histogram.compose()
    };

    Ok(noisy_histogram)
}
