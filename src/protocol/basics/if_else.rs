use crate::{
    error::Error,
    ff::Field,
    protocol::{basics::SecureMul, context::Context, RecordId},
    secret_sharing::{Linear as LinearSecretSharing, LinearRefOps},
};

/// Returns `true_value` if `condition` is a share of 1, else `false_value`.
/// # Errors
/// If the protocol fails to execute.
pub async fn if_else<F, C, S>(
    ctx: C,
    record_id: RecordId,
    condition: &S,
    true_value: &S,
    false_value: &S,
) -> Result<S, Error>
where
    F: Field,
    C: Context,
    S: LinearSecretSharing<F> + SecureMul<C>,
    for<'a> &'a S: LinearRefOps<'a, S, F>,
{
    // If `condition` is a share of 1 (true), then
    //   = false_value + 1 * (true_value - false_value)
    //   = false_value + true_value - false_value
    //   = true_value
    //
    // If `condition` is a share of 0 (false), then
    //   = false_value + 0 * (true_value - false_value)
    //   = false_value
    Ok(false_value
        + &condition
            .multiply(&(true_value - false_value), ctx, record_id)
            .await?)
}
