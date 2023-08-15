use std::marker::PhantomData;

use futures::stream::{iter as stream_iter, Stream, StreamExt};

use crate::{
    error::Error,
    ff::PrimeField,
    protocol::{
        basics::SecureMul,
        context::{prss::InstrumentedIndexedSharedRandomness, Context, UpgradedContext},
        modulus_conversion::{
            convert_bits, convert_some_bits, BitConversionTriple, ToBitConversionTriples,
        },
        prss::SharedRandomness,
        RecordId,
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed,
        Linear as LinearSecretSharing,
    },
};

#[derive(Debug)]
struct RawRandomBits {
    // TODO: use a const generic instead of a field, when generic_const_expr hits stable.
    count: u32,
    left: u64,
    right: u64,
}

impl RawRandomBits {
    fn generate<F: PrimeField>(
        prss: &InstrumentedIndexedSharedRandomness,
        record_id: RecordId,
    ) -> Self {
        // This avoids `F::BITS` as that can be larger than we need.
        let count = u128::BITS - F::PRIME.into().leading_zeros();
        assert!(count <= u64::BITS);
        let (left, right) = prss.generate_values(record_id);
        #[allow(clippy::cast_possible_truncation)] // See above for the relevant assertion.
        Self {
            count,
            left: left as u64,
            right: right as u64,
        }
    }
}

impl ToBitConversionTriples for RawRandomBits {
    // TODO const for this in place of the function
    fn bits(&self) -> u32 {
        self.count
    }

    fn triple<F: PrimeField>(
        &self,
        role: crate::helpers::Role,
        i: u32,
    ) -> BitConversionTriple<Replicated<F>> {
        debug_assert!(u128::BITS - F::PRIME.into().leading_zeros() >= self.count);
        assert!(i < self.count);
        BitConversionTriple::new(
            role,
            ((self.left >> i) & 1) == 1,
            ((self.right >> i) & 1) == 1,
        )
    }
}

struct RawRandomBitIter<F, C> {
    ctx: C,
    record_id: RecordId,
    _f: PhantomData<F>,
}

impl<F: PrimeField, C: Context> Iterator for RawRandomBitIter<F, C> {
    type Item = RawRandomBits;
    fn next(&mut self) -> Option<Self::Item> {
        let v = RawRandomBits::generate::<F>(&self.ctx.prss(), self.record_id);
        self.record_id += 1;
        Some(v)
    }
}

/// Produce a stream of random bits using the provided context.
///
/// # Panics
/// If the provided context has an unspecified total record count.
/// An indeterminate limit works, but setting a fixed value greatly helps performance.
pub fn random_bits<F, C>(ctx: C) -> impl Stream<Item = Result<BitDecomposed<C::Share>, Error>>
where
    F: PrimeField,
    C: UpgradedContext<F>,
    C::Share: LinearSecretSharing<F> + SecureMul<C>,
{
    debug_assert!(ctx.total_records().is_specified());
    let iter = RawRandomBitIter::<F, C> {
        ctx: ctx.clone(),
        record_id: RecordId(0),
        _f: PhantomData,
    };
    let bits = 0..(u128::BITS - F::PRIME.into().leading_zeros());
    convert_bits(ctx, stream_iter(iter), bits)
}

/// # Errors
/// If the conversion is unsuccessful (usually the result of communication errors).
/// # Panics
/// Never, but the compiler doesn't know that.

// TODO : remove this hacky function and make people use the streaming version (which might be harder to use, but is cleaner)
pub async fn one_random_bit<F, C>(
    ctx: C,
    record_id: RecordId,
) -> Result<BitDecomposed<C::Share>, Error>
where
    F: PrimeField,
    C: UpgradedContext<F>,
    C::Share: LinearSecretSharing<F> + SecureMul<C>,
{
    let iter = RawRandomBitIter::<F, C> {
        ctx: ctx.clone(),
        record_id,
        _f: PhantomData,
    };
    let bits = 0..(u128::BITS - F::PRIME.into().leading_zeros());
    Box::pin(convert_some_bits(
        ctx,
        // TODO: For some reason, the input stream is polled 16 times, despite this function only calling "next()" once.
        // That interacts poorly with PRSS, so cap the iterator.
        stream_iter(iter.take(1)),
        record_id,
        bits,
    ))
    .next()
    .await
    .unwrap()
}
