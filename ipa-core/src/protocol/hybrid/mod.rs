pub(crate) mod step;
use std::convert::Infallible;

use crate::{
    error::{Error, LengthError},
    ff::{
        boolean::Boolean,
        boolean_array::{BooleanArray, BA5, BA8},
        curve_points::RP25519,
        ec_prime_field::Fp25519,
        U128Conversions,
    },
    helpers::query::DpMechanism,
    protocol::{
        basics::{BooleanArrayMul, Reveal},
        context::{DZKPUpgraded, MacUpgraded, ShardedContext, UpgradableContext},
        ipa_prf::{oprf_padding::PaddingParameters, prf_eval::PrfSharing, shuffle::Shuffle},
        prss::FromPrss,
        BooleanProtocols,
    },
    report::hybrid::IndistinguishableHybridReport,
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed, FieldSimd,
        TransposeFrom, Vectorizable,
    },
};

// In theory, we could support (runtime-configured breakdown count) ≤ (compile-time breakdown count)
// ≤ 2^|bk|, with all three values distinct, but at present, there is no runtime configuration and
// the latter two must be equal. The implementation of `move_single_value_to_bucket` does support a
// runtime-specified count via the `breakdown_count` parameter, and implements a runtime check of
// its value.
//
// It would usually be more appropriate to make `MAX_BREAKDOWNS` an associated constant rather than
// a const parameter. However, we want to use it to enforce a correct pairing of the `BK` type
// parameter and the `B` const parameter, and specifying a constraint like
// `BreakdownKey<MAX_BREAKDOWNS = B>` on an associated constant is not currently supported. (Nor is
// supplying an associated constant `<BK as BreakdownKey>::MAX_BREAKDOWNS` as the value of a const
// parameter.) Structured the way we have it, it probably doesn't make sense to use the
// `BreakdownKey` trait in places where the `B` const parameter is not already available.
pub trait BreakdownKey<const MAX_BREAKDOWNS: usize>: BooleanArray + U128Conversions {}
impl BreakdownKey<32> for BA5 {}
impl BreakdownKey<256> for BA8 {}

/// Vectorization dimension for share conversion
pub const CONV_CHUNK: usize = 256;

/// Vectorization dimension for PRF
pub const PRF_CHUNK: usize = 16;

/// Vectorization dimension for aggregation.
pub const AGG_CHUNK: usize = 256;

/// The Hybrid Protocol
///
/// This protocol takes in a [`Vec<IndistinguishableHybridReport<BK, V>>`]
/// and aggregates it into a summary report. `HybridReport`s are either
/// impressions or conversion. The protocol joins these based on their matchkeys,
/// sums the values from conversions grouped by the breakdown key on impressions.
/// To accomplish this, hte protocol performs the follwoing steps
///  1. Converts secret-sharings of boolean arrays to secret-sharings of elliptic curve points
///  2. Generates a random number of "dummy records" (needed to mask the information that will
///     be revealed in step 4, and thereby provide a differential privacy guarantee on
///     that information leakage)
///  3. Shuffles the input
///  4. Computes an OPRF of these elliptic curve points and reveals this "pseudonym"
///  5. Groups together rows with the same OPRF and sums both the breakdown keys and values.
///  6. Generates a random number of "dummy records" (needed to mask the information that will
///     be revealed in step 7)
///  7. Shuffles the input
///  8. Reveals breakdown keys
///  9. Sums the values by breakdown keys
/// 10. Adds random noise to the total value for each breakdown key (to provide a
///     differential privacy guarantee)
///
/// # Errors
/// Propagates errors from config issues or while running the protocol
/// # Panics
/// Propagates errors from config issues or while running the protocol
pub async fn hybrid_protocol<'ctx, C, BK, V, HV, const SS_BITS: usize, const B: usize>(
    _ctx: C,
    input_rows: Vec<IndistinguishableHybridReport<BK, V>>,
    _dp_params: DpMechanism,
    _dp_padding_params: PaddingParameters,
) -> Result<Vec<Replicated<HV>>, Error>
where
    C: UpgradableContext + 'ctx + Shuffle + ShardedContext,
    BK: BreakdownKey<B>,
    V: BooleanArray + U128Conversions,
    HV: BooleanArray + U128Conversions,
    Boolean: FieldSimd<B>,
    Replicated<Boolean>: BooleanProtocols<DZKPUpgraded<C>>,
    Replicated<Boolean, B>: BooleanProtocols<DZKPUpgraded<C>, B>,
    Replicated<Boolean, AGG_CHUNK>: BooleanProtocols<DZKPUpgraded<C>, AGG_CHUNK>,
    Replicated<Boolean, CONV_CHUNK>: BooleanProtocols<DZKPUpgraded<C>, CONV_CHUNK>,
    Replicated<Fp25519, PRF_CHUNK>:
        PrfSharing<MacUpgraded<C, Fp25519>, PRF_CHUNK, Field = Fp25519> + FromPrss,
    Replicated<RP25519, PRF_CHUNK>:
        Reveal<MacUpgraded<C, Fp25519>, Output = <RP25519 as Vectorizable<PRF_CHUNK>>::Array>,
    Replicated<BK>: BooleanArrayMul<DZKPUpgraded<C>>
        + Reveal<DZKPUpgraded<C>, Output = <BK as Vectorizable<1>>::Array>,
    Replicated<V>: BooleanArrayMul<DZKPUpgraded<C>>,
    BitDecomposed<Replicated<Boolean, AGG_CHUNK>>:
        for<'a> TransposeFrom<&'a Vec<Replicated<BK>>, Error = LengthError>,
    BitDecomposed<Replicated<Boolean, AGG_CHUNK>>:
        for<'a> TransposeFrom<&'a Vec<Replicated<V>>, Error = LengthError>,
    Vec<BitDecomposed<Replicated<Boolean, B>>>: for<'a> TransposeFrom<
        &'a [BitDecomposed<Replicated<Boolean, AGG_CHUNK>>],
        Error = Infallible,
    >,
    BitDecomposed<Replicated<Boolean, B>>:
        for<'a> TransposeFrom<&'a [Replicated<V>; B], Error = Infallible>,
    Vec<Replicated<HV>>:
        for<'a> TransposeFrom<&'a BitDecomposed<Replicated<Boolean, B>>, Error = LengthError>,
    BitDecomposed<Replicated<Boolean, B>>:
        for<'a> TransposeFrom<&'a [Replicated<HV>; B], Error = Infallible>,
{
    if input_rows.is_empty() {
        return Ok(vec![Replicated::ZERO; B]);
    }
    unimplemented!("protocol::hybrid::hybrid_protocol is not fully implemented")
}
