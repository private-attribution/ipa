use std::iter::zip;

use futures::{stream, StreamExt, TryStreamExt};
use typenum::Const;

use crate::{
    error::{Error, UnwrapInfallible},
    ff::{
        boolean::Boolean,
        boolean_array::{BooleanArray, BA5, BA64, BA8},
        curve_points::RP25519,
        ec_prime_field::Fp25519,
        U128Conversions,
    },
    helpers::{
        stream::{div_round_up, process_slice_by_chunks, Chunk, ChunkData, TryFlattenItersExt},
        TotalRecords,
    },
    protocol::{
        basics::{BooleanProtocols, Reveal},
        context::{
            dzkp_validator::DZKPValidator, DZKPUpgraded, MacUpgraded, MaliciousProtocolSteps,
            UpgradableContext, Validator,
        },
        ipa_prf::{
            boolean_ops::convert_to_fp25519,
            prf_eval::{eval_dy_prf, gen_prf_key, PrfSharing},
            prf_sharding::PrfShardedIpaInputRow,
            step::IpaPrfStep,
            OPRFIPAInputRow,
        },
        prss::FromPrss,
        RecordId,
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed, TransposeFrom,
        Vectorizable,
    },
    seq_join::seq_join,
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
#[allow(dead_code)]
pub trait BreakdownKey<const MAX_BREAKDOWNS: usize>: BooleanArray + U128Conversions {}
impl BreakdownKey<32> for BA5 {}
impl BreakdownKey<256> for BA8 {}

/// Match key type
pub type MatchKey = BA64;

/// Vectorization dimension for share conversion
pub const CONV_CHUNK: usize = 256;

/// Vectorization dimension for PRF
pub const PRF_CHUNK: usize = 16;

// We expect 2*256 = 512 gates in total for two additions per conversion. The vectorization factor
// is CONV_CHUNK. Let `len` equal the number of converted shares. The total amount of
// multiplications is CONV_CHUNK*512*len. We want CONV_CHUNK*512*len ≈ 50M, or len ≈ 381, for a
// reasonably-sized proof. There is also a constraint on proof chunks to be powers of two, so
// we pick the closest power of two close to 381 but less than that value. 256 gives us around 33M
// multiplications per batch
const CONV_PROOF_CHUNK: usize = 256;

#[allow(dead_code)]
#[tracing::instrument(name = "compute_prf_for_inputs", skip_all)]
async fn compute_prf_for_inputs<C, BK, TV, TS>(
    ctx: C,
    input_rows: &[OPRFIPAInputRow<BK, TV, TS>],
) -> Result<Vec<PrfShardedIpaInputRow<BK, TV, TS>>, Error>
where
    C: UpgradableContext,
    BK: BooleanArray,
    TV: BooleanArray,
    TS: BooleanArray,
    Replicated<Boolean, CONV_CHUNK>: BooleanProtocols<DZKPUpgraded<C>, CONV_CHUNK>,
    Replicated<Fp25519, PRF_CHUNK>:
        PrfSharing<MacUpgraded<C, Fp25519>, PRF_CHUNK, Field = Fp25519> + FromPrss,
    Replicated<RP25519, PRF_CHUNK>:
        Reveal<MacUpgraded<C, Fp25519>, Output = <RP25519 as Vectorizable<PRF_CHUNK>>::Array>,
{
    let conv_records =
        TotalRecords::specified(div_round_up(input_rows.len(), Const::<CONV_CHUNK>))?;
    let eval_records = TotalRecords::specified(div_round_up(input_rows.len(), Const::<PRF_CHUNK>))?;
    let convert_ctx = ctx.set_total_records(conv_records);

    let validator = convert_ctx.dzkp_validator(
        MaliciousProtocolSteps {
            protocol: &IpaPrfStep::ConvertFp25519,
            validate: &IpaPrfStep::ConvertFp25519Validate,
        },
        CONV_PROOF_CHUNK,
    );
    let m_ctx = validator.context();

    let curve_pts = seq_join(
        ctx.active_work(),
        process_slice_by_chunks(input_rows, move |idx, records: ChunkData<_, CONV_CHUNK>| {
            let record_id = RecordId::from(idx);
            let input_match_keys: &dyn Fn(usize) -> Replicated<MatchKey> =
                &|i| records[i].match_key.clone();
            let match_keys =
                BitDecomposed::<Replicated<Boolean, 256>>::transposed_from(input_match_keys)
                    .unwrap_infallible();
            convert_to_fp25519::<_, CONV_CHUNK, PRF_CHUNK>(m_ctx.clone(), record_id, match_keys)
        }),
    )
    .map_ok(Chunk::unpack::<PRF_CHUNK>)
    .try_flatten_iters()
    .try_collect::<Vec<_>>()
    .await?;

    let prf_key = gen_prf_key(&ctx.narrow(&IpaPrfStep::PrfKeyGen));
    let validator = ctx
        .narrow(&IpaPrfStep::EvalPrf)
        .set_total_records(eval_records)
        .validator::<Fp25519>();
    let eval_ctx = validator.context();

    let prf_of_match_keys = seq_join(
        ctx.active_work(),
        stream::iter(curve_pts).enumerate().map(|(i, curve_pts)| {
            let record_id = RecordId::from(i);
            let eval_ctx = eval_ctx.clone();
            let prf_key = &prf_key;
            curve_pts
                .then(move |pts| eval_dy_prf::<_, PRF_CHUNK>(eval_ctx, record_id, prf_key, pts))
        }),
    )
    .try_collect::<Vec<_>>()
    .await?;

    Ok(zip(input_rows, prf_of_match_keys.into_iter().flatten())
        .map(|(input, prf_of_match_key)| {
            let OPRFIPAInputRow {
                match_key: _,
                is_trigger,
                breakdown_key,
                trigger_value,
                timestamp,
            } = &input;

            PrfShardedIpaInputRow {
                prf_of_match_key,
                is_trigger_bit: is_trigger.clone(),
                breakdown_key: breakdown_key.clone(),
                trigger_value: trigger_value.clone(),
                timestamp: timestamp.clone(),
                sort_key: Replicated::ZERO,
            }
        })
        .collect())
}
