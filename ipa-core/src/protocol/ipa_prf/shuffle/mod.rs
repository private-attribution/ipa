use std::future::Future;

use futures::FutureExt;

use super::{
    boolean_ops::{expand_shared_array_in_place, extract_from_shared_array},
    prf_sharding::SecretSharedAttributionOutputs,
};
use crate::{
    error::Error,
    ff::{
        boolean::Boolean,
        boolean_array::{BooleanArray, BA112, BA64},
        ArrayAccess,
    },
    helpers::Role,
    protocol::{
        context::{Context, MaliciousContext, SemiHonestContext},
        ipa_prf::{shuffle::sharded::ShuffleContext, OPRFIPAInputRow},
    },
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
        SharedValue,
    },
    sharding::{ShardBinding, Sharded},
};

mod base;
mod malicious;
mod sharded;
pub(crate) mod step; // must be pub(crate) for compact gate gen

use base::shuffle_protocol as base_shuffle;
use malicious::{malicious_sharded_shuffle, malicious_shuffle};
use sharded::shuffle as sharded_shuffle;
pub use sharded::MaliciousShuffleable;

/// This struct stores some intermediate messages during the shuffle.
/// In a maliciously secure shuffle,
/// these messages need to be checked for consistency across helpers.
/// `H1` stores `x1`, `H2` stores `x2` and `H3` stores `y1` and `y2`.
#[derive(Debug, Clone)]
enum IntermediateShuffleMessages<S> {
    H1 { x1: Vec<S> },
    H2 { x2: Vec<S> },
    H3 { y1: Vec<S>, y2: Vec<S> },
}

impl<S> IntermediateShuffleMessages<S> {
    pub fn role(&self) -> Role {
        match *self {
            IntermediateShuffleMessages::H1 { .. } => Role::H1,
            IntermediateShuffleMessages::H2 { .. } => Role::H2,
            IntermediateShuffleMessages::H3 { .. } => Role::H3,
        }
    }

    /// Return an empty `IntermediateShuffleMessages` for the currrent helper.
    pub fn empty<C: Context>(ctx: &C) -> Self {
        match ctx.role() {
            Role::H1 => IntermediateShuffleMessages::H1 { x1: vec![] },
            Role::H2 => IntermediateShuffleMessages::H2 { x2: vec![] },
            Role::H3 => IntermediateShuffleMessages::H3 {
                y1: vec![],
                y2: vec![],
            },
        }
    }
}

/// Trait used by protocols to invoke either semi-honest or malicious non-sharded
/// shuffle, depending on the type of context being used.
pub trait Shuffle: Context {
    fn shuffle<S, I>(self, shares: I) -> impl Future<Output = Result<Vec<S>, Error>> + Send
    where
        S: MaliciousShuffleable,
        I: IntoIterator<Item = S> + Send,
        I::IntoIter: ExactSizeIterator + Send;
}

impl<T: ShardBinding> Shuffle for SemiHonestContext<'_, T> {
    fn shuffle<S, I>(self, shares: I) -> impl Future<Output = Result<Vec<S>, Error>> + Send
    where
        S: MaliciousShuffleable,
        I: IntoIterator<Item = S> + Send,
        I::IntoIter: ExactSizeIterator + Send,
    {
        let fut = base_shuffle::<_, S, _>(self, shares);
        fut.map(|res| res.map(|(output, _intermediates)| output))
    }
}

impl<T: ShardBinding> Shuffle for MaliciousContext<'_, T> {
    fn shuffle<S, I>(self, shares: I) -> impl Future<Output = Result<Vec<S>, Error>> + Send
    where
        S: MaliciousShuffleable,
        I: IntoIterator<Item = S> + Send,
        I::IntoIter: ExactSizeIterator + Send,
    {
        malicious_shuffle::<_, S, _>(self, shares)
    }
}

/// Trait used by protocols to invoke either semi-honest or malicious sharded shuffle,
/// depending on the type of context being used.
#[allow(dead_code)]
pub trait ShardedShuffle: ShuffleContext {
    fn sharded_shuffle<S, I>(self, shares: I) -> impl Future<Output = Result<Vec<S>, Error>> + Send
    where
        S: MaliciousShuffleable,
        I: IntoIterator<Item = S> + Send,
        I::IntoIter: ExactSizeIterator + Send;
}

impl ShardedShuffle for SemiHonestContext<'_, Sharded> {
    fn sharded_shuffle<S, I>(self, shares: I) -> impl Future<Output = Result<Vec<S>, Error>> + Send
    where
        S: MaliciousShuffleable,
        I: IntoIterator<Item = S> + Send,
        I::IntoIter: ExactSizeIterator + Send,
    {
        let fut = sharded_shuffle::<_, S, _>(self, shares);
        fut.map(|res| res.map(|(output, _intermediates)| output))
    }
}

impl ShardedShuffle for MaliciousContext<'_, Sharded> {
    fn sharded_shuffle<S, I>(self, shares: I) -> impl Future<Output = Result<Vec<S>, Error>> + Send
    where
        S: MaliciousShuffleable,
        I: IntoIterator<Item = S> + Send,
        I::IntoIter: ExactSizeIterator + Send,
    {
        malicious_sharded_shuffle::<_, S, _>(self, shares)
    }
}

#[tracing::instrument(name = "shuffle_inputs", skip_all)]
pub async fn shuffle_inputs<C, BK, TV, TS>(
    ctx: C,
    input: Vec<OPRFIPAInputRow<BK, TV, TS>>,
) -> Result<Vec<OPRFIPAInputRow<BK, TV, TS>>, Error>
where
    C: Context + Shuffle,
    BK: BooleanArray,
    TV: BooleanArray,
    TS: BooleanArray,
{
    let shuffle_input: Vec<AdditiveShare<BA112>> = input
        .into_iter()
        .map(|item| oprfreport_to_shuffle_input::<BA112, BK, TV, TS>(&item))
        .collect::<Vec<_>>();

    let shuffled = ctx
        .shuffle::<AdditiveShare<BA112>, _>(shuffle_input)
        .await?;

    Ok(shuffled
        .into_iter()
        .map(|item| shuffled_to_oprfreport(&item))
        .collect::<Vec<_>>())
}

#[tracing::instrument(name = "shuffle_attribution_outputs", skip_all)]
pub async fn shuffle_attribution_outputs<C, BK, TV, R>(
    ctx: C,
    input: Vec<SecretSharedAttributionOutputs<BK, TV>>,
) -> Result<Vec<SecretSharedAttributionOutputs<BK, TV>>, Error>
where
    C: Context + Shuffle,
    BK: BooleanArray,
    TV: BooleanArray,
    R: BooleanArray,
    AdditiveShare<R>: MaliciousShuffleable,
{
    let shuffle_input: Vec<AdditiveShare<R>> = input
        .into_iter()
        .map(|item| attribution_outputs_to_shuffle_input::<BK, TV, R>(&item))
        .collect::<Vec<_>>();

    let shuffled = ctx.shuffle::<AdditiveShare<R>, _>(shuffle_input).await?;

    Ok(shuffled
        .into_iter()
        .map(|item| shuffled_to_attribution_outputs::<R, BK, TV>(&item))
        .collect::<Vec<_>>())
}

// This function converts OprfReport to an AdditiveShare needed for shuffle protocol
pub fn oprfreport_to_shuffle_input<YS, BK, TV, TS>(
    input: &OPRFIPAInputRow<BK, TV, TS>,
) -> AdditiveShare<YS>
where
    YS: BooleanArray,
    BK: BooleanArray,
    TV: BooleanArray,
    TS: BooleanArray,
{
    let mut y = ReplicatedSecretSharing::new(YS::ZERO, YS::ZERO);
    expand_shared_array_in_place(&mut y, &input.match_key, 0);

    let mut offset = BA64::BITS as usize;

    y.set(offset, input.is_trigger.clone());

    offset += 1;

    expand_shared_array_in_place(&mut y, &input.breakdown_key, offset);

    offset += BK::BITS as usize;
    expand_shared_array_in_place(&mut y, &input.trigger_value, offset);

    offset += TV::BITS as usize;
    expand_shared_array_in_place(&mut y, &input.timestamp, offset);

    y
}

// This function converts AdditiveShare obtained from shuffle protocol to OprfReport
pub fn shuffled_to_oprfreport<YS, BK, TV, TS>(
    input: &AdditiveShare<YS>,
) -> OPRFIPAInputRow<BK, TV, TS>
where
    YS: BooleanArray,
    BK: BooleanArray,
    TV: BooleanArray,
    TS: BooleanArray,
{
    let match_key = extract_from_shared_array::<YS, BA64>(input, 0);

    let mut offset = BA64::BITS as usize;

    let is_trigger = ReplicatedSecretSharing::new(
        input.left().get(offset).unwrap_or(Boolean::ZERO),
        input.right().get(offset).unwrap_or(Boolean::ZERO),
    );

    offset += 1;

    let breakdown_key = extract_from_shared_array::<YS, BK>(input, offset);

    offset += BK::BITS as usize;
    let trigger_value = extract_from_shared_array::<YS, TV>(input, offset);

    offset += TV::BITS as usize;
    let timestamp = extract_from_shared_array::<YS, TS>(input, offset);

    OPRFIPAInputRow {
        match_key,
        is_trigger,
        breakdown_key,
        trigger_value,
        timestamp,
    }
}

// This function converts Attribution Outputs to an AdditiveShare needed for shuffle protocol
pub fn attribution_outputs_to_shuffle_input<BK, TV, YS>(
    input: &SecretSharedAttributionOutputs<BK, TV>,
) -> AdditiveShare<YS>
where
    YS: BooleanArray,
    BK: BooleanArray,
    TV: BooleanArray,
{
    let mut y = ReplicatedSecretSharing::new(YS::ZERO, YS::ZERO);
    expand_shared_array_in_place(&mut y, &input.attributed_breakdown_key_bits, 0);
    expand_shared_array_in_place(
        &mut y,
        &input.capped_attributed_trigger_value,
        BK::BITS as usize,
    );
    y
}

// This function converts Attribution Outputs  obtained from shuffle protocol to OprfReport
pub fn shuffled_to_attribution_outputs<YS, BK, TV>(
    input: &AdditiveShare<YS>,
) -> SecretSharedAttributionOutputs<BK, TV>
where
    YS: BooleanArray,
    BK: BooleanArray,
    TV: BooleanArray,
{
    let attributed_breakdown_key_bits = extract_from_shared_array::<YS, BK>(input, 0);
    let capped_attributed_trigger_value =
        extract_from_shared_array::<YS, TV>(input, BK::BITS as usize);

    SecretSharedAttributionOutputs {
        attributed_breakdown_key_bits,
        capped_attributed_trigger_value,
    }
}

#[cfg(all(test, unit_test))]
pub mod tests {
    use rand::Rng;

    use crate::{
        ff::{
            boolean_array::{BA20, BA3, BA32, BA64, BA8},
            U128Conversions,
        },
        protocol::ipa_prf::{
            prf_sharding::{
                tests::PreAggregationTestOutputInDecimal, AttributionOutputsTestInput,
                SecretSharedAttributionOutputs,
            },
            shuffle::{shuffle_attribution_outputs, shuffle_inputs},
        },
        test_executor::run,
        test_fixture::{ipa::TestRawDataRecord, Reconstruct, Runner, TestWorld},
    };

    fn input_row(
        bk: u128,
        tv: u128,
    ) -> (
        AttributionOutputsTestInput<BA32, BA32>,
        PreAggregationTestOutputInDecimal,
    ) {
        let bk_bits = BA32::truncate_from(bk);
        let tv_bits = BA32::truncate_from(tv);
        (
            AttributionOutputsTestInput {
                bk: bk_bits,
                tv: tv_bits,
            },
            PreAggregationTestOutputInDecimal {
                attributed_breakdown_key: bk_bits.as_u128(),
                capped_attributed_trigger_value: tv_bits.as_u128(),
            },
        )
    }

    #[test]
    fn test_shuffle_inputs() {
        const BATCHSIZE: usize = 50;
        run(|| async {
            let world = TestWorld::default();

            let mut rng = rand::thread_rng();
            let mut records = Vec::new();

            for _ in 0..BATCHSIZE {
                records.push({
                    TestRawDataRecord {
                        timestamp: rng.gen_range(0u64..1 << 20),
                        user_id: rng.gen::<u64>(),
                        is_trigger_report: rng.gen::<bool>(),
                        breakdown_key: rng.gen_range(0u32..1 << 8),
                        trigger_value: rng.gen_range(0u32..1 << 3),
                    }
                });
            }

            let mut result: Vec<TestRawDataRecord> = world
                .semi_honest(records.clone().into_iter(), |ctx, input_rows| async move {
                    shuffle_inputs::<_, BA8, BA3, BA20>(ctx, input_rows)
                        .await
                        .unwrap()
                })
                .await
                .reconstruct();
            assert_ne!(result, records);
            records.sort();
            result.sort();
            assert_eq!(result, records);
        });
    }

    #[test]
    fn test_shuffle_attribution_outputs() {
        const BATCHSIZE: usize = 50;
        run(|| async {
            let world = TestWorld::default();
            let mut rng = rand::thread_rng();
            let mut inputs = Vec::new();
            let mut expectation = Vec::new();
            for _ in 0..BATCHSIZE {
                let (i, e) =
                    input_row(rng.gen_range(0u128..1 << 32), rng.gen_range(0u128..1 << 32));
                inputs.push(i);
                expectation.push(e);
            }
            let mut result: Vec<PreAggregationTestOutputInDecimal> = world
                .semi_honest(inputs.into_iter(), |ctx, input_rows| async move {
                    let aos: Vec<_> = input_rows
                        .into_iter()
                        .map(|ti| SecretSharedAttributionOutputs {
                            attributed_breakdown_key_bits: ti.0,
                            capped_attributed_trigger_value: ti.1,
                        })
                        .collect();
                    shuffle_attribution_outputs::<_, BA32, BA32, BA64>(ctx, aos)
                        .await
                        .unwrap()
                })
                .await
                .reconstruct();
            assert_ne!(result, expectation);
            expectation.sort();
            result.sort();
            assert_eq!(result, expectation);
        });
    }
}
