use std::iter::zip;

use crate::{
    error::Error,
    ff::boolean::Boolean,
    protocol::{basics::SecureMul, boolean::step::BitOpStep, context::Context, RecordId},
    secret_sharing::{replicated::semi_honest::AdditiveShare, BitDecomposed, FieldSimd},
};

/// Matrix bitwise AND for use with vectors of bit-decomposed values
///
/// ## Errors
/// Propagates errors from the multiplication protocol.
/// ## Panics
/// Panics if the bit-decomposed arguments do not have the same length.
//
// Supplying an iterator saves constructing a complete copy of the argument
// in memory when it is a uniform constant.
pub async fn bool_and<'a, C, BI, const N: usize>(
    ctx: C,
    record_id: RecordId,
    a: &BitDecomposed<AdditiveShare<Boolean, N>>,
    b: BI,
) -> Result<BitDecomposed<AdditiveShare<Boolean, N>>, Error>
where
    C: Context,
    BI: IntoIterator,
    <BI as IntoIterator>::IntoIter: ExactSizeIterator<Item = &'a AdditiveShare<Boolean, N>> + Send,
    Boolean: FieldSimd<N>,
    AdditiveShare<Boolean, N>: SecureMul<C>,
{
    let b = b.into_iter();
    assert_eq!(a.len(), b.len());

    BitDecomposed::try_from(
        ctx.parallel_join(zip(a.iter(), b).enumerate().map(|(i, (a, b))| {
            let ctx = ctx.narrow(&BitOpStep::Bit(i));
            a.multiply(b, ctx, record_id)
        }))
        .await?,
    )
}
