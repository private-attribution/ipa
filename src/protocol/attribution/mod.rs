pub mod aggregate_credit;
pub mod credit_capping;

pub(crate) mod accumulate_credit;

use crate::{
    bits::Serializable,
    error::Error,
    ff::Field,
    protocol::{context::Context, RecordId, Substep},
    repeat64str,
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated,
        Arithmetic as ArithmeticSecretSharing, SecretSharing,
    },
};
use std::io;

#[derive(Debug, Clone)]
pub struct AttributionInputRow<F: Field> {
    pub is_trigger_bit: Replicated<F>,
    pub helper_bit: Replicated<F>,
    pub breakdown_key: Replicated<F>,
    pub credit: Replicated<F>,
}

pub type AccumulateCreditOutputRow<F> = AttributionInputRow<F>;

pub type CreditCappingInputRow<F> = AccumulateCreditOutputRow<F>;

pub struct CreditCappingOutputRow<F: Field> {
    breakdown_key: Replicated<F>,
    credit: Replicated<F>,
}

#[derive(Clone, Debug)]
pub struct CappedCreditsWithAggregationBit<F: Field> {
    helper_bit: Replicated<F>,
    aggregation_bit: Replicated<F>,
    breakdown_key: Replicated<F>,
    credit: Replicated<F>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct AggregateCreditOutputRow<F: Field> {
    breakdown_key: Replicated<F>,
    credit: Replicated<F>,
}

impl<F: Field> AggregateCreditOutputRow<F> {
    /// Splits the given slice into chunks aligned with the size of this struct and returns an
    /// iterator that produces deserialized instances.
    ///
    /// ## Panics
    /// Panics if the slice buffer is not aligned with the size of this struct.
    pub fn from_byte_slice(slice: &[u8]) -> impl Iterator<Item = Self> + '_ {
        assert_eq!(0, slice.len() % Self::SIZE_IN_BYTES);

        slice
            .chunks(Self::SIZE_IN_BYTES)
            .map(|chunk| Self::deserialize(chunk).unwrap())
    }
}

impl<F: Field> Serializable for AggregateCreditOutputRow<F> {
    const SIZE_IN_BYTES: usize = Replicated::<F>::SIZE_IN_BYTES * 2;

    fn serialize(self, buf: &mut [u8]) -> io::Result<()> {
        self.breakdown_key.serialize(buf)?;
        self.credit
            .serialize(&mut buf[Replicated::<F>::SIZE_IN_BYTES..])?;

        Ok(())
    }

    fn deserialize(buf: &[u8]) -> io::Result<Self> {
        let breakdown_key = Replicated::<F>::deserialize(buf)?;
        let credit = Replicated::<F>::deserialize(&buf[Replicated::<F>::SIZE_IN_BYTES..])?;

        Ok(Self {
            breakdown_key,
            credit,
        })
    }
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
    S: ArithmeticSecretSharing<F>,
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

async fn compute_stop_bit<F, C, S>(
    ctx: C,
    record_id: RecordId,
    b_bit: &S,
    sibling_stop_bit: &S,
    first_iteration: bool,
) -> Result<S, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    // This method computes `b == 1 ? sibling_stop_bit : 0`.
    // Since `sibling_stop_bit` is initialize with 1, we return `b` if this is
    // the first iteration.
    if first_iteration {
        return Ok(b_bit.clone());
    }
    ctx.multiply(record_id, b_bit, sibling_stop_bit).await
}

async fn compute_b_bit<F, C, S>(
    ctx: C,
    record_id: RecordId,
    current_stop_bit: &S,
    sibling_helper_bit: &S,
    first_iteration: bool,
) -> Result<S, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    // Compute `b = [this.stop_bit * sibling.helper_bit]`.
    // Since `stop_bit` is initialized with all 1's, we only multiply in
    // the second and later iterations.
    let mut b = sibling_helper_bit.clone();
    if !first_iteration {
        b = ctx
            .multiply(record_id, sibling_helper_bit, current_stop_bit)
            .await?;
    }
    Ok(b)
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
pub enum AttributionResharableStep {
    IsTriggerBit,
    HelperBit,
    BreakdownKey,
    Credit,
    AggregationBit,
}

impl Substep for AttributionResharableStep {}

impl AsRef<str> for AttributionResharableStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::IsTriggerBit => "is_trigger_bit",
            Self::HelperBit => "helper_bit",
            Self::BreakdownKey => "breakdown_key",
            Self::Credit => "credit",
            Self::AggregationBit => "aggregation_bit",
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use crate::secret_sharing::IntoShares;
    use crate::{ff::Field, protocol::attribution::AttributionInputRow};
    use rand::{distributions::Standard, prelude::Distribution, rngs::mock::StepRng};
    use std::iter::zip;

    pub const S: u128 = 0;
    pub const T: u128 = 1;
    pub const H: [u128; 2] = [0, 1];
    pub const BD: [u128; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

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
            let itb = F::from(x[0]).share_with(rng);
            let hb = F::from(x[1]).share_with(rng);
            let bk = F::from(x[2]).share_with(rng);
            let val = F::from(x[3]).share_with(rng);
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
