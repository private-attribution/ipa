use crate::{
    error::Error, ff::PrimeField, helpers::query::IpaQueryConfig, protocol::context::Context,
    secret_sharing::Linear as LinearSecretSharing,
};
use std::borrow::BorrowMut;

pub async fn differential_privacy<C, B, T, F>(
    _ctx: C,
    config: &IpaQueryConfig,
    values: &mut [B],
) -> Result<(), Error>
where
    C: Context,
    B: BorrowMut<T>,
    T: LinearSecretSharing<F>,
    F: PrimeField,
{
    let Some(_dp) = config.dp.as_ref() else { return Ok(()); };
    for v in values {
        _ = *v.borrow();
    }
    Ok(())
}
