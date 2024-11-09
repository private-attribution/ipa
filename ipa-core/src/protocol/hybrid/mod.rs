pub(crate) mod oprf;
pub(crate) mod step;

use crate::{
    error::Error,
    ff::{
        boolean::Boolean, boolean_array::BooleanArray, curve_points::RP25519,
        ec_prime_field::Fp25519, Serializable, U128Conversions,
    },
    helpers::query::DpMechanism,
    protocol::{
        basics::{BooleanProtocols, Reveal},
        context::{DZKPUpgraded, MacUpgraded, ShardedContext, UpgradableContext},
        hybrid::{
            oprf::{compute_prf_and_reshard, BreakdownKey, CONV_CHUNK, PRF_CHUNK},
            step::HybridStep as Step,
        },
        ipa_prf::{
            oprf_padding::{apply_dp_padding, PaddingParameters},
            prf_eval::PrfSharing,
            shuffle::Shuffle,
        },
        prss::FromPrss,
    },
    report::hybrid::{IndistinguishableHybridReport, PrfHybridReport},
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, Vectorizable},
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
    _dp_params: DpMechanism,
    dp_padding_params: PaddingParameters,
) -> Result<Vec<Replicated<HV>>, Error>
where
    C: UpgradableContext + 'ctx + Shuffle + ShardedContext,
    BK: BreakdownKey<B>,
    V: BooleanArray + U128Conversions,
    HV: BooleanArray + U128Conversions,
    Replicated<Boolean, CONV_CHUNK>: BooleanProtocols<DZKPUpgraded<C>, CONV_CHUNK>,
    Replicated<Fp25519, PRF_CHUNK>:
        PrfSharing<MacUpgraded<C, Fp25519>, PRF_CHUNK, Field = Fp25519> + FromPrss,
    Replicated<RP25519, PRF_CHUNK>:
        Reveal<MacUpgraded<C, Fp25519>, Output = <RP25519 as Vectorizable<PRF_CHUNK>>::Array>,
    PrfHybridReport<BK, V>: Serializable,
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

    // TODO shuffle input rows
    let shuffled_input_rows = padded_input_rows;

    let _sharded_reports = compute_prf_and_reshard(ctx.clone(), shuffled_input_rows).await?;

    unimplemented!("protocol::hybrid::hybrid_protocol is not fully implemented")
}
