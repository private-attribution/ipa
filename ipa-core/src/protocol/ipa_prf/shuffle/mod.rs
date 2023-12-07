use self::base::shuffle;
use crate::{
    error::Error,
    ff::{
        boolean::Boolean,
        boolean_array::{BA112, BA64},
        ArrayAccess, CustomArray, Expand, Field,
    },
    protocol::context::{UpgradableContext, UpgradedContext},
    report::OprfReport,
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
        SharedValue,
    },
};

pub mod base;

#[tracing::instrument(name = "shuffle_inputs", skip_all)]
async fn shuffle_inputs<C, BK, TV, TS>(
    ctx: C,
    input: Vec<OprfReport<BK, TV, TS>>,
) -> Result<Vec<OprfReport<BK, TV, TS>>, Error>
where
    C: UpgradableContext,
    C::UpgradedContext<Boolean>: UpgradedContext<Boolean, Share = AdditiveShare<Boolean>>,
    BK: SharedValue + CustomArray<Element = Boolean> + Field,
    TV: SharedValue + CustomArray<Element = Boolean> + Field,
    TS: SharedValue + CustomArray<Element = Boolean> + Field,
    for<'a> &'a AdditiveShare<TS>: IntoIterator<Item = AdditiveShare<Boolean>>,
    for<'a> &'a AdditiveShare<TV>: IntoIterator<Item = AdditiveShare<Boolean>>,
    for<'a> &'a AdditiveShare<BK>: IntoIterator<Item = AdditiveShare<Boolean>>,
    for<'a> <&'a AdditiveShare<TV> as IntoIterator>::IntoIter: Send,
    for<'a> <&'a AdditiveShare<TS> as IntoIterator>::IntoIter: Send,
{
    let shuffle_input: Vec<AdditiveShare<BA112>> = input
        .into_iter()
        .map(|item| oprfreport_to_shuffle_input::<BA112, BK, TV, TS>(&item))
        .collect::<Vec<_>>();

    let shuffled = shuffle(ctx, shuffle_input).await?;

    Ok(shuffled
        .into_iter()
        .map(|item| shuffled_to_oprfreport(&item))
        .collect::<Vec<_>>())
}

fn expand_array_in_place<YS, XS>(y: &mut YS, x: XS, offset: usize, size: u32)
where
    YS: CustomArray<Element = <BA112 as CustomArray>::Element> + SharedValue,
    XS: SharedValue + ArrayAccess<Output = Boolean> + Expand<Input = Boolean>,
{
    for i in 0..size as usize {
        y.set(i + offset, x.get(i).unwrap_or(Boolean::ZERO));
    }
}

// This function converts OprfReport to an AdditiveShare needed for shuffle protocol
pub fn oprfreport_to_shuffle_input<YS, BK, TV, TS>(
    input: &OprfReport<BK, TV, TS>,
) -> AdditiveShare<YS>
where
    YS: CustomArray<Element = <BA112 as CustomArray>::Element> + SharedValue,
    BK: SharedValue + ArrayAccess<Output = Boolean> + Expand<Input = Boolean>,
    TV: SharedValue + ArrayAccess<Output = Boolean> + Expand<Input = Boolean>,
    TS: SharedValue + ArrayAccess<Output = Boolean> + Expand<Input = Boolean>,
{
    let (mut y_left, mut y_right) = (YS::ZERO, YS::ZERO);
    expand_array_in_place(&mut y_left, input.match_key.left(), 0, BA64::BITS);
    expand_array_in_place(&mut y_right, input.match_key.right(), 0, BA64::BITS);

    let mut offset = BA64::BITS as usize;

    y_left.set(offset, input.is_trigger.left());
    y_right.set(offset, input.is_trigger.right());

    offset += 1;

    expand_array_in_place(&mut y_left, input.breakdown_key.left(), offset, BK::BITS);
    expand_array_in_place(&mut y_right, input.breakdown_key.right(), offset, BK::BITS);

    offset += BK::BITS as usize;
    expand_array_in_place(&mut y_left, input.trigger_value.left(), offset, TV::BITS);
    expand_array_in_place(&mut y_right, input.trigger_value.right(), offset, TV::BITS);

    offset += TV::BITS as usize;
    expand_array_in_place(&mut y_left, input.timestamp.left(), offset, TS::BITS);
    expand_array_in_place(&mut y_right, input.timestamp.right(), offset, TS::BITS);

    AdditiveShare::<YS>::new(y_left, y_right)
}

// This function converts AdditiveShare obtained from shuffle protocol to OprfReport
pub fn shuffled_to_oprfreport<YS, BK, TV, TS>(input: &AdditiveShare<YS>) -> OprfReport<BK, TV, TS>
where
    YS: SharedValue + ArrayAccess<Output = Boolean> + Expand<Input = Boolean>,
    BK: SharedValue + ArrayAccess<Output = Boolean> + Expand<Input = Boolean>,
    TV: SharedValue + ArrayAccess<Output = Boolean> + Expand<Input = Boolean>,
    TS: SharedValue + ArrayAccess<Output = Boolean> + Expand<Input = Boolean>,
{
    let (mut match_key_left, mut match_key_right) = (BA64::ZERO, BA64::ZERO);
    for i in 0..BA64::BITS as usize {
        match_key_left.set(
            i,
            input
                .left()
                .get(i)
                .unwrap_or(<BA64 as CustomArray>::Element::ZERO),
        );
        match_key_right.set(
            i,
            input
                .right()
                .get(i)
                .unwrap_or(<BA64 as CustomArray>::Element::ZERO),
        );
    }
    let mut offset = BA64::BITS as usize;

    let is_trigger = AdditiveShare::<Boolean>::new(
        input.left().get(offset).unwrap_or(Boolean::ZERO),
        input.right().get(offset).unwrap_or(Boolean::ZERO),
    );

    offset += 1;

    let (mut breakdown_key_left, mut breakdown_key_right) = (BK::ZERO, BK::ZERO);
    for i in 0..BK::BITS as usize {
        breakdown_key_left.set(
            i,
            input
                .left()
                .get(i + offset)
                .unwrap_or(<BK as CustomArray>::Element::ZERO),
        );
        breakdown_key_right.set(
            i,
            input
                .right()
                .get(i + offset)
                .unwrap_or(<BK as CustomArray>::Element::ZERO),
        );
    }
    offset += BK::BITS as usize;
    let (mut trigger_value_left, mut trigger_value_right) = (TV::ZERO, TV::ZERO);
    for i in 0..TV::BITS as usize {
        trigger_value_left.set(
            i,
            input
                .left()
                .get(i + offset)
                .unwrap_or(<TV as CustomArray>::Element::ZERO),
        );
        trigger_value_right.set(
            i,
            input
                .right()
                .get(i + offset)
                .unwrap_or(<TV as CustomArray>::Element::ZERO),
        );
    }

    offset += TV::BITS as usize;
    let (mut timestamp_left, mut timestamp_right) = (TS::ZERO, TS::ZERO);
    for i in 0..TS::BITS as usize {
        timestamp_left.set(
            i,
            input
                .left()
                .get(i + offset)
                .unwrap_or(<TS as CustomArray>::Element::ZERO),
        );
        timestamp_right.set(
            i,
            input
                .right()
                .get(i + offset)
                .unwrap_or(<TS as CustomArray>::Element::ZERO),
        );
    }
    OprfReport {
        match_key: AdditiveShare::<BA64>::new(match_key_left, match_key_right),
        is_trigger,
        breakdown_key: AdditiveShare::<BK>::new(breakdown_key_left, breakdown_key_right),
        trigger_value: AdditiveShare::<TV>::new(trigger_value_left, trigger_value_right),
        timestamp: AdditiveShare::<TS>::new(timestamp_left, timestamp_right),
    }
}

#[cfg(all(test, unit_test))]
pub mod tests {
    use rand::Rng;

    use crate::{
        ff::boolean_array::{BA20, BA3, BA8},
        protocol::ipa_prf::shuffle::shuffle_inputs,
        test_executor::run,
        test_fixture::{ipa::TestRawDataRecord, Reconstruct, Runner, TestWorld},
    };

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
}
