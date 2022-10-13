use crate::secret_sharing::Replicated;

mod accumulate;

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Copy, Clone)]
pub struct AttributionInputRow<F> {
    is_trigger_bit: Replicated<F>,
    helper_bit: Replicated<F>,
    #[allow(dead_code)]
    breakdown_key: Replicated<F>,
    value: Replicated<F>,
}

pub struct AccumulationInputRow<F> {
    stop_bit: Replicated<F>,
    credit: Replicated<F>,
    report: AttributionInputRow<F>,
}

#[allow(dead_code)]
pub struct AccumulationOutputRow<F> {
    breakdown_key: Replicated<F>,
    credit: Replicated<F>,
    aggregation_bit: Replicated<F>,
}
