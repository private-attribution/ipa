use crate::{ff::Field, secret_sharing::Replicated};

mod accumulate_credit;
mod credit_capping;

#[derive(Debug, Clone)]
pub struct AttributionInputRow<F: Field> {
    is_trigger_bit: Replicated<F>,
    helper_bit: Replicated<F>,
    #[allow(dead_code)]
    breakdown_key: Replicated<F>,
    credit: Replicated<F>,
}

pub struct InteractionPatternInputRow<F: Field> {
    is_trigger_bit: Replicated<F>,
    helper_bit: Replicated<F>,
    stop_bit: Replicated<F>,
    interaction_bit: Replicated<F>,
}

pub type AccumulateCreditOutputRow<F> = AttributionInputRow<F>;

pub type CreditCappingInputRow<F> = AccumulateCreditOutputRow<F>;

pub type CreditCappingOutputRow<F> = CreditCappingInputRow<F>;
