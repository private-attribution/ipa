use crate::{ff::Field, secret_sharing::Replicated};

mod accumulate_credit;

#[derive(Debug, Clone)]
pub struct AttributionInputRow<F: Field> {
    is_trigger_bit: Replicated<F>,
    helper_bit: Replicated<F>,
    #[allow(dead_code)]
    breakdown_key: Replicated<F>,
    value: Replicated<F>,
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
