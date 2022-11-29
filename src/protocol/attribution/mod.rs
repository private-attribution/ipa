use crate::{ff::Field, secret_sharing::Replicated};

use super::Substep;

mod accumulate_credit;

#[derive(Debug, Clone, PartialEq)]
pub struct AttributionInputRow<F: Field> {
    pub is_trigger_bit: Replicated<F>,
    pub helper_bit: Replicated<F>,
    #[allow(dead_code)]
    pub breakdown_key: Replicated<F>,
    pub value: Replicated<F>,
}

pub struct AccumulateCreditInputRow<F: Field> {
    stop_bit: Replicated<F>,
    credit: Replicated<F>,
    report: AttributionInputRow<F>,
}

#[allow(dead_code)]
pub struct AccumulateCreditOutputRow<F: Field> {
    breakdown_key: Replicated<F>,
    credit: Replicated<F>,
    aggregation_bit: Replicated<F>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum AttributionInputRowResharableStep {
    IsTriggerBit,
    HelperBit,
    BreakdownKey,
    Value,
}

impl Substep for AttributionInputRowResharableStep {}

impl AsRef<str> for AttributionInputRowResharableStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::IsTriggerBit => "is_trigger_bit",
            Self::HelperBit => "helper_bit",
            Self::BreakdownKey => "breakdown_key",
            Self::Value => "value",
        }
    }
}
