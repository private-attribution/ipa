use std::cmp::max;

use futures::{stream, StreamExt, TryStreamExt};
use typenum::Const;

use crate::{
    error::{Error, UnwrapInfallible},
    ff::{
        boolean::Boolean,
        boolean_array::{BooleanArray, BA5, BA64, BA8},
        curve_points::RP25519,
        ec_prime_field::Fp25519,
        Serializable, U128Conversions,
    },
    helpers::{
        stream::{div_round_up, process_slice_by_chunks, Chunk, ChunkData, TryFlattenItersExt},
        TotalRecords,
    },
    protocol::{
        basics::{BooleanProtocols, Reveal},
        context::{
            dzkp_validator::{prev_power_of_two, DZKPValidator, TARGET_PROOF_SIZE},
            reshard_try_stream, DZKPUpgraded, MacUpgraded, MaliciousProtocolSteps, ShardedContext,
            UpgradableContext, Validator,
        },
        hybrid::step::HybridStep,
        ipa_prf::{
            boolean_ops::convert_to_fp25519,
            prf_eval::{eval_dy_prf, PrfSharing},
        },
        prss::{FromPrss, SharedRandomness},
        RecordId,
    },
    report::hybrid::{IndistinguishableHybridReport, PrfHybridReport},
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

/// Returns a suitable proof chunk size (in records) for use with `convert_to_fp25519`.
///
/// We expect 2*256 = 512 gates in total for two additions per conversion. The
/// vectorization factor is `CONV_CHUNK`. Let `len` equal the number of converted
/// shares. The total amount of multiplications is `CONV_CHUNK`*512*len. We want
/// `CONV_CHUNK`*512*len ≈ 50M for a reasonably-sized proof. There is also a constraint
/// on proof chunks to be powers of two, and we don't want to compute a proof chunk
/// of zero when `TARGET_PROOF_SIZE` is smaller for tests.
fn conv_proof_chunk() -> usize {
    prev_power_of_two(max(2, TARGET_PROOF_SIZE / CONV_CHUNK / 512))
}

#[tracing::instrument(name = "compute_prf_for_inputs", skip_all)]
pub async fn compute_prf_and_reshard<C, BK, V>(
    ctx: C,
    input_rows: Vec<IndistinguishableHybridReport<BK, V>>,
) -> Result<Vec<PrfHybridReport<BK, V>>, Error>
where
    C: UpgradableContext + ShardedContext,
    BK: BooleanArray,
    V: BooleanArray,
    Replicated<Boolean, CONV_CHUNK>: BooleanProtocols<DZKPUpgraded<C>, CONV_CHUNK>,
    Replicated<Fp25519, PRF_CHUNK>:
        PrfSharing<MacUpgraded<C, Fp25519>, PRF_CHUNK, Field = Fp25519> + FromPrss,
    Replicated<RP25519, PRF_CHUNK>:
        Reveal<MacUpgraded<C, Fp25519>, Output = <RP25519 as Vectorizable<PRF_CHUNK>>::Array>,
    PrfHybridReport<BK, V>: Serializable,
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
        conv_proof_chunk(),
    );
    let m_ctx = validator.context();

    let curve_pts = seq_join(
        ctx.active_work(),
        process_slice_by_chunks(
            &input_rows,
            move |idx, records: ChunkData<_, CONV_CHUNK>| {
                let record_id = RecordId::from(idx);
                let input_match_keys: &dyn Fn(usize) -> Replicated<MatchKey> =
                    &|i| records[i].match_key.clone();
                let match_keys =
                    BitDecomposed::<Replicated<Boolean, 256>>::transposed_from(input_match_keys)
                        .unwrap_infallible();
                convert_to_fp25519::<_, CONV_CHUNK, PRF_CHUNK>(m_ctx.clone(), record_id, match_keys)
            },
        ),
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
    .try_flatten_iters();

    let report_stream = prf_of_match_keys
        .zip(stream::iter(input_rows))
        // map from (Result<X>, T) to Result<(X, T)>
        .map(|(mk, input)| mk.map(|mk| (mk, input)))
        .map_ok(|(prf_of_match_key, input)| PrfHybridReport {
            match_key: prf_of_match_key,
            value: input.value,
            breakdown_key: input.breakdown_key,
        });

    // reshard reports based on OPRF values. This ensures at the end of this function
    // reports with the same value end up on the same shard.
    reshard_try_stream(ctx, report_stream, |ctx, _, report| {
        report.match_key % ctx.shard_count()
    })
    .await
}

/// generates PRF key k as secret sharing over Fp25519
pub fn gen_prf_key<C, const N: usize>(ctx: &C) -> Replicated<Fp25519, N>
where
    C: UpgradableContext + ShardedContext,
    Fp25519: Vectorizable<N>,
{
    let v: Replicated<Fp25519, 1> = ctx.cross_shard_prss().generate(RecordId::FIRST);

    v.expand()
}

#[cfg(all(test, unit_test, feature = "in-memory-infra"))]
mod test {
    use std::collections::{HashMap, HashSet};

    use ipa_step::StepNarrow;

    use crate::{
        ff::boolean_array::{BA3, BA8},
        protocol::{hybrid::oprf::compute_prf_and_reshard, step::ProtocolStep, Gate},
        report::hybrid::{IndistinguishableHybridReport, PrfHybridReport},
        test_executor::run,
        test_fixture::{hybrid::TestHybridRecord, Runner, TestWorld, TestWorldConfig, WithShards},
    };

    #[test]
    fn hybrid_oprf() {
        run(|| async {
            const SHARDS: usize = 2;
            let world: TestWorld<WithShards<SHARDS>> = TestWorld::with_shards(TestWorldConfig {
                initial_gate: Some(Gate::default().narrow(&ProtocolStep::Hybrid)),
                ..Default::default()
            });

            let records = [
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

            // TODO: we need to use malicious circuits here
            let reports_per_shard = world
                .semi_honest(records.clone().into_iter(), |ctx, reports| async move {
                    let ind_reports = reports
                        .into_iter()
                        .map(IndistinguishableHybridReport::from)
                        .collect();
                    compute_prf_and_reshard(ctx, ind_reports).await.unwrap()
                })
                .await;

            // exactly two unique PRF values on every helper
            assert_eq!(
                2,
                reports_per_shard
                    .iter()
                    .flat_map(|v| v.iter().flat_map(Clone::clone))
                    .map(|report| report.match_key)
                    .collect::<HashSet<_>>()
                    .len(),
            );

            // every unique match key belongs to a single shard, and it is consistent across helpers
            let mut global_mk = HashMap::new();
            reports_per_shard
                .into_iter()
                .enumerate()
                .for_each(|(shard_id, [h1, h2, h3])| {
                    fn extractor(
                        shard_id: usize,
                        input: Vec<PrfHybridReport<BA8, BA3>>,
                    ) -> HashMap<u64, usize> {
                        input
                            .into_iter()
                            .map(|report| (report.match_key, shard_id))
                            .collect()
                    }
                    let m1 = extractor(shard_id, h1);
                    let m2 = extractor(shard_id, h2);
                    let m3 = extractor(shard_id, h3);

                    // it is ok for some shards to have empty list, so len check is not required
                    assert_eq!(
                        m1, m2,
                        "h1 and h2 helper PRF values don't match: {m1:?} != {m2:?}"
                    );
                    assert_eq!(
                        m2, m3,
                        "h2 and h3 helper PRF values don't match: {m2:?} != {m3:?}"
                    );

                    for key in m1.keys() {
                        global_mk.entry(*key).or_insert(Vec::new()).push(shard_id);
                    }
                });
            let mk_on_shards = global_mk.values().map(Vec::len).collect::<HashSet<_>>();
            assert_eq!(1, mk_on_shards.len());
            assert_eq!(Some(&1), mk_on_shards.get(&1));
        });
    }
}
