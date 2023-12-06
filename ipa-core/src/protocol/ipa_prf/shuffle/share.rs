use crate::{
    ff::{
        boolean::Boolean,
        boolean_array::{BA112, BA64},
        ArrayAccess, CustomArray, Expand,
    },
    report::OprfReport,
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
        SharedValue,
    },
};

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

    for i in 0..BA64::BITS as usize {
        y_left.set(
            i,
            input
                .match_key
                .left()
                .get(i)
                .unwrap_or(<BA64 as CustomArray>::Element::ZERO),
        );
        y_right.set(
            i,
            input
                .match_key
                .right()
                .get(i)
                .unwrap_or(<BA64 as CustomArray>::Element::ZERO),
        );
    }

    let mut offset = BA64::BITS as usize;

    y_left.set(offset, input.is_trigger.left());
    y_right.set(offset, input.is_trigger.right());

    offset += 1;

    for i in 0..BK::BITS as usize {
        y_left.set(
            i + offset,
            input
                .breakdown_key
                .left()
                .get(i)
                .unwrap_or(<BK as CustomArray>::Element::ZERO),
        );
        y_right.set(
            i + offset,
            input
                .breakdown_key
                .right()
                .get(i)
                .unwrap_or(<BK as CustomArray>::Element::ZERO),
        );
    }
    offset += BK::BITS as usize;
    for i in 0..TV::BITS as usize {
        y_left.set(
            i + offset,
            input
                .trigger_value
                .left()
                .get(i)
                .unwrap_or(<TV as CustomArray>::Element::ZERO),
        );
        y_right.set(
            i + offset,
            input
                .trigger_value
                .right()
                .get(i)
                .unwrap_or(<TV as CustomArray>::Element::ZERO),
        );
    }

    offset += TV::BITS as usize;
    for i in 0..TS::BITS as usize {
        y_left.set(
            i + offset,
            input
                .timestamp
                .left()
                .get(i)
                .unwrap_or(<TS as CustomArray>::Element::ZERO),
        );
        y_right.set(
            i + offset,
            input
                .timestamp
                .right()
                .get(i)
                .unwrap_or(<TS as CustomArray>::Element::ZERO),
        );
    }
    AdditiveShare::<YS>::new(y_left, y_right)
}

// This function converts AdditiveShare obtained from shuffle protocol to OprfReport
pub fn shuffled_to_oprfreport<YS, BK, TV, TS>(input: &AdditiveShare<YS>) -> OprfReport<BK, TV, TS>
where
    // YS: CustomArray<Element = <YS as CustomArray>::Element> + SharedValue,
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
