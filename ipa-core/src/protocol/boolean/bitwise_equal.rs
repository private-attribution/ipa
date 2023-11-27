use std::iter::zip;

use crate::{
    error::Error,
    ff::Gf2,
    protocol::{boolean::all_zeroes, context::Context, BasicProtocols, RecordId},
    secret_sharing::{Linear as LinearSecretSharing, LinearRefOps},
};

///
/// # Errors
/// Propagates errors from multiplications
///
pub async fn bitwise_equal_gf2<C, S>(
    ctx: C,
    record_id: RecordId,
    a: &[S],
    b: &[S],
) -> Result<S, Error>
where
    C: Context,
    S: LinearSecretSharing<Gf2> + BasicProtocols<C, Gf2>,
    for<'a> &'a S: LinearRefOps<'a, S, Gf2>,
{
    debug_assert!(a.len() == b.len());
    let c = zip(a.iter(), b.iter())
        .map(|(a_bit, b_bit)| a_bit - b_bit)
        .collect::<Vec<_>>();

    all_zeroes(ctx, record_id, &c).await
}
