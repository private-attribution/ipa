use std::{iter::from_fn, marker::PhantomData};

use crate::{
    error::Error,
    ff::PrimeField,
    protocol::{
        basics::SecureMul,
        context::{prss::InstrumentedIndexedSharedRandomness, Context, UpgradedContext},
        modulus_conversion::{convert_some_bits, BitConversionTriple, ToBitConversionTriples},
        prss::SharedRandomness,
        RecordId,
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, Linear as LinearSecretSharing,
        SharedValue,
    },
};
use futures::stream::{iter as stream_iter, Stream, StreamExt};

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
        assert!(<F as SharedValue>::BITS <= u64::BITS);
        let (left, right) = prss.generate_values(record_id);
        Self {
            count: <F as SharedValue>::BITS,
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
        debug_assert!(F::BITS >= self.count);
        BitConversionTriple::new(role, (self.left >> i) == 1, (self.right >> i) == 1)
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
pub fn random_bits<F, C>(ctx: C) -> impl Stream<Item = Result<Vec<C::Share>, Error>>
where
    F: PrimeField,
    C: UpgradedContext<F>,
    C::Share: LinearSecretSharing<F> + SecureMul<C>,
{
    let iter = RawRandomBitIter::<F, C> {
        ctx: ctx.clone(),
        record_id: RecordId(0),
        _f: PhantomData,
    };
    convert_some_bits(ctx, stream_iter(iter), 0..F::BITS)
}

// TODO : remove this hacky function and make people use the streaming version (which might be harder to use, but is cleaner)
pub async fn one_random_bit<F, C>(ctx: C, record_id: RecordId) -> Result<Vec<C::Share>, Error>
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
    Box::pin(convert_some_bits(ctx, stream_iter(iter), 0..F::BITS))
        .next()
        .await
        .unwrap()
}
