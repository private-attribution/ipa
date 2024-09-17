use std::iter::zip;

use crate::{
    error::Error,
    ff::boolean::Boolean,
    protocol::{
        basics::SecureMul,
        boolean::{step::EightBitStep, NBitStep},
        context::Context,
        RecordId,
    },
    secret_sharing::{replicated::semi_honest::AdditiveShare, BitDecomposed, FieldSimd},
};

/// Matrix bitwise AND for use with vectors of bit-decomposed values. Supports up to 8 bits of input
/// that is enough to support both WALR and PRF IPA use cases.
///
/// In IPA this function is used to process trigger values and 8 bit is enough to represent them.
/// WALR uses it on feature-vector where 8 bits are used to represent decimals.
/// Limiting the number of bits helps with our static compact gate compilation, so we want this
/// number to be as small as possible.
///
/// ## Errors
/// Propagates errors from the multiplication protocol.
/// ## Panics
/// Panics if the bit-decomposed arguments do not have the same length.
//
// Supplying an iterator saves constructing a complete copy of the argument
// in memory when it is a uniform constant.
pub async fn bool_and_8_bit<'a, C, BI, const N: usize>(
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
        a.len() <= usize::try_from(EightBitStep::BITS).unwrap(),
        "Up to {max_bits} bit values are supported, but was given a value of {len} bits",
        max_bits = EightBitStep::BITS,
        len = a.len()
    );

    BitDecomposed::try_from(
        ctx.parallel_join(zip(a.iter(), b).enumerate().map(|(i, (a, b))| {
            let ctx = ctx.narrow(&EightBitStep::from(i));
            a.multiply(b, ctx, record_id)
        }))
        .await?,
    )
}
