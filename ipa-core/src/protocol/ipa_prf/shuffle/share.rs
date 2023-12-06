use crate::ff::boolean::Boolean;
use crate::ff::Expand;
use crate::secret_sharing::replicated::semi_honest::AdditiveShare;
use crate::{
    ff::{
        boolean_array::{BA112, BA64},
        ArrayAccess, CustomArray,
    },
    report::OprfReport,
    secret_sharing::{replicated::ReplicatedSecretSharing, SharedValue},
};

/// inserts a smaller array into a larger
/// we don't use it right except for testing purposes
pub fn convert_to_share<YS, BK, TV, TS>(input: OprfReport<BK, TV, TS>) -> AdditiveShare<YS>
where
    YS: CustomArray<Element = <BA112 as CustomArray>::Element> + SharedValue,
    BK: SharedValue + ArrayAccess<Output = Boolean> + Expand<Input = Boolean>,
    TV: SharedValue + ArrayAccess<Output = Boolean> + Expand<Input = Boolean>,
    TS: SharedValue + ArrayAccess<Output = Boolean> + Expand<Input = Boolean>,
{
    let y = AdditiveShare::<YS>(YS::ZERO, YS::ZERO);
    for i in 0..BA64::BITS as usize {
        y.left().set(
            i,
            input
                .match_key
                .left()
                .get(i)
                .unwrap_or(<BA64 as CustomArray>::Element::ZERO),
        );
        y.right().set(
            i,
            input
                .match_key
                .right()
                .get(i)
                .unwrap_or(<BA64 as CustomArray>::Element::ZERO),
        );
    }
    let mut offset = BA64::BITS as usize;

    y.left().set(offset, input.is_trigger.left());
    y.right().set(offset, input.is_trigger.right());

    offset += 1;

    for i in 0..BK::BITS as usize {
        y.left().set(
            i + offset,
            input
                .breakdown_key
                .left()
                .get(i)
                .unwrap_or(<BK as CustomArray>::Element::ZERO),
        );
        y.right().set(
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
        y.left().set(
            i + offset,
            input
                .trigger_value
                .left()
                .get(i)
                .unwrap_or(<TV as CustomArray>::Element::ZERO),
        );
        y.right().set(
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
        y.left().set(
            i + offset,
            input
                .timestamp
                .left()
                .get(i)
                .unwrap_or(<TS as CustomArray>::Element::ZERO),
        );
        y.right().set(
            i + offset,
            input
                .timestamp
                .right()
                .get(i)
                .unwrap_or(<TS as CustomArray>::Element::ZERO),
        );
    }
    y
}

/// we don't use it right except for testing purposes
pub fn convert_back_oprf_report<YS, BK, TV, TS>(input: AdditiveShare<YS>) -> OprfReport<BK, TV, TS>
where
    // YS: CustomArray<Element = <YS as CustomArray>::Element> + SharedValue,
    YS: SharedValue + ArrayAccess<Output = Boolean> + Expand<Input = Boolean>,
    BK: SharedValue + ArrayAccess<Output = Boolean> + Expand<Input = Boolean>,
    TV: SharedValue + ArrayAccess<Output = Boolean> + Expand<Input = Boolean>,
    TS: SharedValue + ArrayAccess<Output = Boolean> + Expand<Input = Boolean>,
{
    let match_key = AdditiveShare::<BA64>::new(BA64::ZERO, BA64::ZERO);
    for i in 0..BA64::BITS as usize {
        match_key.left().set(
            i,
            input
                .left()
                .get(i)
                .unwrap_or(<BA64 as CustomArray>::Element::ZERO),
        );
        match_key.right().set(
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

    let breakdown_key = AdditiveShare::<BK>::new(BK::ZERO, BK::ZERO);
    for i in 0..BK::BITS as usize {
        breakdown_key.left().set(
            i,
            input
                .left()
                .get(i + offset)
                .unwrap_or(<BK as CustomArray>::Element::ZERO),
        );
        breakdown_key.right().set(
            i,
            input
                .right()
                .get(i + offset)
                .unwrap_or(<BK as CustomArray>::Element::ZERO),
        );
    }
    offset += BK::BITS as usize;
    let trigger_value: AdditiveShare<TV> = AdditiveShare::<TV>::new(TV::ZERO, TV::ZERO);
    for i in 0..TV::BITS as usize {
        trigger_value.left().set(
            i,
            input
                .left()
                .get(i + offset)
                .unwrap_or(<TV as CustomArray>::Element::ZERO),
        );
        trigger_value.right().set(
            i,
            input
                .right()
                .get(i + offset)
                .unwrap_or(<TV as CustomArray>::Element::ZERO),
        );
    }

    offset += TV::BITS as usize;
    let timestamp: AdditiveShare<TS> = AdditiveShare::<TS>::new(TS::ZERO, TS::ZERO);
    for i in 0..TS::BITS as usize {
        timestamp.left().set(
            i,
            input
                .left()
                .get(i + offset)
                .unwrap_or(<TS as CustomArray>::Element::ZERO),
        );
        timestamp.right().set(
            i,
            input
                .right()
                .get(i + offset)
                .unwrap_or(<TS as CustomArray>::Element::ZERO),
        );
    }
    OprfReport {
        match_key,
        is_trigger,
        breakdown_key,
        trigger_value,
        timestamp,
    }
}
