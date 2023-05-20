use crate::{
    error::Error,
    ff::PrimeField,
    protocol::{
        context::{Context, UpgradedContext},
        modulus_conversion::{convert_all_bits, BitConversionTriple, ToBitConversionTriples},
        prss::{IndexedSharedRandomness, SharedRandomness},
        RecordId,
    },
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing},
        SharedValue,
    },
};
use futures::{
    future::ready,
    stream::{once, unfold, Stream},
};

struct RawRandomBits {
    // TODO: use a const generic instead of a field, when generic_const_expr hits stable.
    count: u32,
    left: u64,
    right: u64,
}

impl RawRandomBits {
    fn generate<C: UpgradedContext<F>, F: PrimeField>(
        prss: &IndexedSharedRandomness,
        record_id: RecordId,
    ) -> Self {
        assert!(<F as SharedValue>::BITS <= u64::BITS);
        let (left, right) = prss.generate_values(record_id);
        Self {
            count: <F as SharedValue>::BITS,
            left,
            right,
        }
    }
}

impl ToBitConversionTriples for RawRandomBits {
    fn to_triples<F: PrimeField>(
        &self,
        role: crate::helpers::Role,
    ) -> Vec<BitConversionTriple<Replicated<F>>> {
        debug_assert!(F::BITS >= self.count);
        (0..self.count)
            .map(|i| BitConversionTriple::new(role, (self.left >> i) == 1, (self.right >> i) == 1))
            .collect::<Vec<_>>()
    }
}

/// Produce a stream of random bits using the provided context.
pub fn random_bits<C: UpgradedContext<F>, F: PrimeField>(
    ctx: C,
) -> impl Stream<Item = Result<Vec<C::Share>, Error>> {
    let randomness = unfold((ctx.clone().prss(), 0), |(prss, i)| {
        Some((RawRandomBits::generate(&prss, i), (prss, i + 1)))
    })
    .take(
        ctx.total_records()
            .count()
            .expect("random_bits needs a fixed number of records"),
    );
    convert_all_bits(ctx, randomness)
}

// TODO : remove this hacky function and make people use the streaming version (which might be harder to use, but is cleaner
pub async fn one_random_bit<C: UpgradedContext<F>, F: PrimeField>(
    ctx: C,
    record_id: RecordId,
) -> Result<Vec<C::Share>, Error> {
    let randomness = once(ready(RawRandomBits::generate(&ctx.prss(), record_id)));
    convert_all_bits(ctx, randomness).next().await
}
