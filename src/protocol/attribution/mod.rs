use crate::secret_sharing::Replicated;

mod accumulate_credit;

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Copy, Clone)]
pub struct AttributionInputRow<F> {
    is_trigger_bit: Replicated<F>,
    helper_bit: Replicated<F>,
    #[allow(dead_code)]
    breakdown_key: Replicated<F>,
    value: Replicated<F>,
}

pub struct AccumulateCreditInputRow<F> {
    stop_bit: Replicated<F>,
    credit: Replicated<F>,
    report: AttributionInputRow<F>,
}

#[allow(dead_code)]
pub struct AccumulateCreditOutputRow<F> {
    breakdown_key: Replicated<F>,
    credit: Replicated<F>,
    aggregation_bit: Replicated<F>,
}

struct IterStep {
    name: &'static str,
    count: u32,
    id: String,
}

impl IterStep {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            count: 0,
            id: String::from(name),
        }
    }

    fn next(&mut self) -> &Self {
        self.count += 1;
        self.id = format!("{}_{}", self.name, self.count);
        self
    }

    fn is_first_iteration(&self) -> bool {
        self.count == 1
    }
}

impl crate::protocol::Substep for IterStep {}

impl AsRef<str> for IterStep {
    fn as_ref(&self) -> &str {
        self.id.as_str()
    }
}
