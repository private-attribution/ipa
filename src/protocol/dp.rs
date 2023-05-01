use crate::{
    error::Error, ff::PrimeField, helpers::query::IpaQueryConfig, protocol::context::Context,
    secret_sharing::Linear as LinearSecretSharing,
};

/// Apply differential privacy to the provided values.
/// # Errors
/// If the protocol does not successfully execute.
#[allow(clippy::unused_async)]
pub async fn differential_privacy<C, B, T, F>(
    _ctx: C,
    config: &IpaQueryConfig,
    values: &mut [B],
) -> Result<(), Error>
where
    C: Context,
    B: AsMut<T>,
    T: LinearSecretSharing<F>,
    F: PrimeField,
{
    let Some(_dp) = config.dp.as_ref() else { return Ok(()); };
    for v in values {
        _ = *v.as_mut();
    }
    Ok(())
}
