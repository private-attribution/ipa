use std::iter::zip;

use ipa_macros::Step;

use crate::{
    error::Error,
    ff::boolean::Boolean,
    protocol::{basics::SecureMul, context::Context, RecordId},
    secret_sharing::{replicated::semi_honest::AdditiveShare, BitDecomposed, FieldSimd},
};

const MAX_BITS: usize = 9;

#[derive(Step)]
pub(crate) enum BoolAndStep {
    #[dynamic(9)] // keep in sync with MAX_BITS
    Bit(usize),
}

/// Matrix bitwise AND for use with vectors of bit-decomposed values. Supports up to 9 bits of input
/// that is enough to support both WALR and PRF IPA use cases. IPA currently supports up to
/// 512 breakdowns (see [`MAX_BREAKDOWN`] limitation) and WALR does not need more than that.
/// Limiting the number of bits helps with our static compact gate compilation, so we want this
/// number to be as small as possible.
///
/// [`MAX_BREAKDOWN`]: crate::protocol::ipa_prf::aggregation::bucket::move_single_value_to_bucket
///
/// ## Errors
/// Propagates errors from the multiplication protocol.
/// ## Panics
/// Panics if the bit-decomposed arguments do not have the same length.
//
// Supplying an iterator saves constructing a complete copy of the argument
// in memory when it is a uniform constant.
pub async fn bool_and_9_bit<'a, C, BI, const N: usize>(
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
    assert!(
        a.len() <= MAX_BITS,
        "Up to {MAX_BITS} values are supported, but was given a value of {len} bits",
        len = a.len()
    );

    BitDecomposed::try_from(
        ctx.parallel_join(zip(a.iter(), b).enumerate().map(|(i, (a, b))| {
            let ctx = ctx.narrow(&BoolAndStep::Bit(i));
            a.multiply(b, ctx, record_id)
        }))
        .await?,
    )
}
