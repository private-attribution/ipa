use crate::error::Error;
use crate::ff::Field;
use crate::protocol::{context::Context, RecordId, Substep};
use crate::repeat64str;
use crate::secret_sharing::{Arithmetic as ArithmeticSecretSharing, SecretSharing};

pub(crate) mod accumulate_credit;
pub mod aggregate_credit;
pub mod credit_capping;
pub mod input;

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
