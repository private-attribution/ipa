use crate::{ff::Field, secret_sharing::Replicated};

use super::Substep;

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
    interaction_value: Replicated<F>,
}

pub type AccumulateCreditOutputRow<F> = AttributionInputRow<F>;

pub type CreditCappingInputRow<F> = AccumulateCreditOutputRow<F>;

pub type CreditCappingOutputRow<F> = CreditCappingInputRow<F>;

enum InteractionPatternStep {
    Depth(usize),
}

impl Substep for InteractionPatternStep {}

impl AsRef<str> for InteractionPatternStep {
    fn as_ref(&self) -> &str {
        const DEPTH: [&str; 32] = [
            "depth0", "depth1", "depth2", "depth3", "depth4", "depth5", "depth6", "depth7",
            "depth8", "depth9", "depth10", "depth11", "depth12", "depth13", "depth14", "depth15",
            "depth16", "depth17", "depth18", "depth19", "depth20", "depth21", "depth22", "depth23",
            "depth24", "depth25", "depth26", "depth27", "depth28", "depth29", "depth30", "depth31",
        ];
        match self {
            Self::Depth(i) => DEPTH[*i],
        }
    }
}
