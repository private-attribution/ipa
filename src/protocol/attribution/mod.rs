use super::Substep;
use crate::{ff::Field, secret_sharing::Replicated};

pub(crate) mod accumulate_credit;
mod credit_capping;

#[derive(Debug, Clone)]
pub struct AttributionInputRow<F: Field> {
    pub is_trigger_bit: Replicated<F>,
    pub helper_bit: Replicated<F>,
    pub breakdown_key: Replicated<F>,
    pub credit: Replicated<F>,
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum AttributionInputRowResharableStep {
    IsTriggerBit,
    HelperBit,
    BreakdownKey,
    Credit,
}

impl Substep for AttributionInputRowResharableStep {}

impl AsRef<str> for AttributionInputRowResharableStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::IsTriggerBit => "is_trigger_bit",
            Self::HelperBit => "helper_bit",
            Self::BreakdownKey => "breakdown_key",
            Self::Credit => "credit",
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ff::Field, protocol::attribution::AttributionInputRow, protocol::batch::Batch,
        test_fixture::share,
    };
    use rand::{distributions::Standard, prelude::Distribution, rngs::mock::StepRng};
    use std::iter::zip;

    /// Takes a vector of 4-element vectors (e.g., `RAW_INPUT`), and create
    /// shares of `AttributionInputRow`.
    // TODO: Implement a `IntoShares` for any struct
    pub fn generate_shared_input<F: Field>(
        input: &[[u128; 5]],
        rng: &mut StepRng,
    ) -> [Batch<AttributionInputRow<F>>; 3]
    where
        Standard: Distribution<F>,
    {
        let num_rows = input.len();
        let mut shares = [
            Vec::with_capacity(num_rows),
            Vec::with_capacity(num_rows),
            Vec::with_capacity(num_rows),
        ];

        for x in input {
            let itb = share(F::from(x[0]), rng);
            let hb = share(F::from(x[1]), rng);
            let bk = share(F::from(x[2]), rng);
            let val = share(F::from(x[3]), rng);
            for (i, ((itb, hb), (bk, val))) in zip(zip(itb, hb), zip(bk, val)).enumerate() {
                shares[i].push(AttributionInputRow {
                    is_trigger_bit: itb,
                    helper_bit: hb,
                    breakdown_key: bk,
                    credit: val,
                });
            }
        }

        assert_eq!(shares[0].len(), shares[1].len());
        assert_eq!(shares[1].len(), shares[2].len());

        [
            Batch::try_from(shares[0].clone()).unwrap(),
            Batch::try_from(shares[1].clone()).unwrap(),
            Batch::try_from(shares[2].clone()).unwrap(),
        ]
    }
}
