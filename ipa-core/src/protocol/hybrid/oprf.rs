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
        hybrid::step::HybridStep,
        ipa_prf::{
            boolean_ops::convert_to_fp25519,
            prf_eval::{eval_dy_prf, gen_prf_key, PrfSharing},
        },
        prss::FromPrss,
        RecordId,
    },
    report::hybrid::IndistinguishableHybridReport,
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed, SharedValue,
        TransposeFrom, Vectorizable,
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
//
// These could be imported from src/protocl/ipa_prf/mod.rs
// however we've copy/pasted them here with the intention of deleting that file [TODO]
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

#[derive(Default, Debug)]
#[allow(dead_code)] // needed to mute warning until used in future PRs
pub struct PRFIndistinguishableHybridReport<BK: SharedValue, V: SharedValue> {
    prf_of_match_key: u64,
    value: Replicated<V>,
    breakdown_key: Replicated<BK>,
}

#[tracing::instrument(name = "compute_prf_for_inputs", skip_all)]
pub async fn compute_prf_for_inputs<C, BK, V>(
    ctx: C,
    input_rows: &[IndistinguishableHybridReport<BK, V>],
) -> Result<Vec<PRFIndistinguishableHybridReport<BK, V>>, Error>
where
    C: UpgradableContext,
    BK: BooleanArray,
    V: BooleanArray,
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
            protocol: &HybridStep::ConvertFp25519,
            validate: &HybridStep::ConvertFp25519Validate,
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

    let prf_key = gen_prf_key(&ctx.narrow(&HybridStep::PrfKeyGen));
    let validator = ctx
        .narrow(&HybridStep::EvalPrf)
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
            let IndistinguishableHybridReport {
                match_key: _,
                value,
                breakdown_key,
            } = &input;

            PRFIndistinguishableHybridReport {
                prf_of_match_key,
                value: value.clone(),
                breakdown_key: breakdown_key.clone(),
            }
        })
        .collect())
}

#[cfg(test)]
mod test {

    use crate::{
        ff::boolean_array::{BA3, BA8},
        protocol::hybrid::oprf::compute_prf_for_inputs,
        report::hybrid::{HybridReport, IndistinguishableHybridReport},
        secret_sharing::IntoShares,
        test_fixture::{
            flatten3v, hybrid::TestHybridRecord, RoundRobinInputDistribution, TestWorld,
            TestWorldConfig, WithShards,
        },
    };

    #[tokio::test]
    async fn hybrid_oprf() {
        let world: TestWorld<WithShards<SHARDS, RoundRobinInputDistribution>> =
            TestWorld::with_shards(TestWorldConfig::default());

        let contexts = world.contexts();

        const SHARDS: usize = 2;

        let records = vec![
            TestHybridRecord::TestImpression {
                match_key: 12345,
                breakdown_key: 2,
            },
            TestHybridRecord::TestImpression {
                match_key: 68362,
                breakdown_key: 1,
            },
            TestHybridRecord::TestConversion {
                match_key: 12345,
                value: 5,
            },
            TestHybridRecord::TestConversion {
                match_key: 68362,
                value: 2,
            },
            TestHybridRecord::TestImpression {
                match_key: 68362,
                breakdown_key: 1,
            },
            TestHybridRecord::TestConversion {
                match_key: 68362,
                value: 7,
            },
        ];

        let shares: [Vec<HybridReport<BA8, BA3>>; 3] = records.iter().cloned().share();

        let indistinguishable_reports: [Vec<IndistinguishableHybridReport<BA8, BA3>>; 3] = shares
            .iter()
            .map(|s| s.into_iter().map(|r| r.clone().into()).collect::<Vec<_>>())
            .collect::<Vec<_>>()
            .try_into()
            .expect("Expected exactly 3 elements");

        let chunked_reports: [Vec<Vec<IndistinguishableHybridReport<BA8, BA3>>>; 3] =
            indistinguishable_reports
                .iter()
                .map(|vec| {
                    let mid = vec.len() / 2;
                    vec.chunks(mid)
                        .map(|chunk| chunk.to_vec())
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
                .try_into()
                .expect("Expected exactly 3 elements");

        #[allow(clippy::large_futures)]
        let results = flatten3v(chunked_reports.into_iter().zip(contexts).map(
            |(reports_by_helper, helper_ctxs)| {
                reports_by_helper
                    .into_iter()
                    .zip(helper_ctxs)
                    .map(|(reports, ctx)| compute_prf_for_inputs(ctx, &reports))
            },
        ))
        .await;

        // println!("{:?}", results);
        // panic!()
    }
}
