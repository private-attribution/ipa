use crate::error::Error;
use crate::ff::Field;
use crate::protocol::{context::Context, RecordId, Substep};
use crate::repeat64str;
use crate::secret_sharing::{Replicated, SecretSharing};

pub(crate) mod accumulate_credit;
mod credit_capping;

#[derive(Debug, Clone)]
pub struct AttributionInputRow<F: Field> {
    pub is_trigger_bit: Replicated<F>,
    pub helper_bit: Replicated<F>,
    pub breakdown_key: Replicated<F>,
    pub credit: Replicated<F>,
}

pub type AccumulateCreditOutputRow<F> = AttributionInputRow<F>;

pub type CreditCappingInputRow<F> = AccumulateCreditOutputRow<F>;

#[allow(dead_code)]
pub struct CreditCappingOutputRow<F: Field> {
    helper_bit: Replicated<F>,
    breakdown_key: Replicated<F>,
    credit: Replicated<F>,
}

/// Returns `true_value` if `condition` is a share of 1, else `false_value`.
async fn if_else<F, C, S>(
    ctx: C,
    record_id: RecordId,
    condition: &S,
    true_value: &S,
    false_value: &S,
) -> Result<S, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    // If `condition` is a share of 1 (true), then
    //   = false_value + 1 * (true_value - false_value)
    //   = false_value + true_value - false_value
    //   = true_value
    //
    // If `condition` is a share of 0 (false), then
    //   = false_value + 0 * (true_value - false_value)
    //   = false_value
    Ok(false_value.clone()
        + &ctx
            .multiply(record_id, condition, &(true_value.clone() - false_value))
            .await?)
}

struct InteractionPatternStep(usize);

impl Substep for InteractionPatternStep {}

impl AsRef<str> for InteractionPatternStep {
    fn as_ref(&self) -> &str {
        const DEPTH: [&str; 64] = repeat64str!["depth"];
        DEPTH[self.0]
    }
}

impl From<usize> for InteractionPatternStep {
    fn from(v: usize) -> Self {
        Self(v)
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
    use crate::{ff::Field, protocol::attribution::AttributionInputRow, test_fixture::share};
    use rand::{distributions::Standard, prelude::Distribution, rngs::mock::StepRng};
    use std::iter::zip;

    /// Takes a vector of 4-element vectors (e.g., `RAW_INPUT`), and create
    /// shares of `AttributionInputRow`.
    // TODO: Implement a `IntoShares` for any struct
    pub fn generate_shared_input<F: Field>(
        input: &[[u128; 5]],
        rng: &mut StepRng,
    ) -> [Vec<AttributionInputRow<F>>; 3]
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

        shares
    }
}
