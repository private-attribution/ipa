pub mod aggregate_credit;
pub mod credit_capping;
pub mod input;

pub(crate) mod accumulate_credit;

use crate::{
    bits::Serializable,
    error::Error,
    ff::Field,
    protocol::{
        attribution::input::MCAggregateCreditOutputRow, context::Context, RecordId, Substep,
    },
    repeat64str,
    secret_sharing::{Arithmetic as ArithmeticSecretSharing, SecretSharing},
};
use generic_array::GenericArray;

impl<F: Field> MCAggregateCreditOutputRow<F> {
    /// Splits the given slice into chunks aligned with the size of this struct and returns an
    /// iterator that produces deserialized instances.
    ///
    /// ## Panics
    /// Panics if the slice buffer is not aligned with the size of this struct.
    pub fn from_byte_slice(slice: &[u8]) -> impl Iterator<Item = Self> + '_ {
        assert_eq!(0, slice.len() % Self::Size::USIZE);

        slice
            .chunks(Self::Size::USIZE)
            .map(|chunk| Self::deserialize(GenericArray::clone_from_slice(chunk)).unwrap())
    }
}

// TODO: fix serialization here
// impl<F: Field> Serializable for AggregateCreditOutputRow<F> {
//     const SIZE_IN_BYTES: usize = Replicated::<F>::SIZE_IN_BYTES * 2;
//
//     fn serialize(self, buf: &mut [u8]) -> io::Result<()> {
//         self.breakdown_key.serialize(buf)?;
//         self.credit
//             .serialize(&mut buf[Replicated::<F>::SIZE_IN_BYTES..])?;
//
//         Ok(())
//     }
//
//     fn deserialize(buf: &[u8]) -> io::Result<Self> {
//         let breakdown_key = Replicated::<F>::deserialize(buf)?;
//         let credit = Replicated::<F>::deserialize(&buf[Replicated::<F>::SIZE_IN_BYTES..])?;
//
//         Ok(Self {
//             breakdown_key,
//             credit,
//         })
//     }
// }

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
