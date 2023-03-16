use crate::{
    error::Error,
    ff::{Field, GaloisField, Gf40Bit, PrimeField},
    protocol::{
        basics::SecureMul,
        context::Context,
        modulus_conversion::{convert_bit, convert_bit_local, BitConversionTriple},
        prss::SharedRandomness,
        BitOpStep, RecordId,
    },
    secret_sharing::{
        replicated::{
            semi_honest::{AdditiveShare as Replicated, XorShare as XorReplicated},
            ReplicatedSecretSharing,
        },
        Linear as LinearSecretSharing, SecretSharing, SharedValue,
    },
};
use async_trait::async_trait;
use futures::future::try_join_all;

mod malicious;
mod semi_honest;

#[async_trait]
pub trait RandomBits<V: SharedValue> {
    type Share: SecretSharing<V>;

    async fn generate_random_bits(self, record_id: RecordId) -> Result<Vec<Self::Share>, Error>;
}

fn random_bits_triples<F, C>(
    ctx: &C,
    record_id: RecordId,
) -> Vec<BitConversionTriple<Replicated<F>>>
where
    F: PrimeField,
    C: Context,
{
    // Calculate the number of bits we need to form a random number that
    // has the same number of bits as the prime.
    let l = u128::BITS - F::PRIME.into().leading_zeros();

    // Generate a pair of random numbers. We'll use these numbers as
    // the source of `l`-bit long uniformly random sequence of bits.
    let (b_bits_left, b_bits_right) = ctx.prss().generate_values(record_id);

    // Same here. For now, 256-bit is enough for our F_p
    let xor_share = XorReplicated::new(
        Gf40Bit::truncate_from(b_bits_left),
        Gf40Bit::truncate_from(b_bits_right),
    );

    // Convert each bit to secret sharings of that bit in the target field
    (0..l)
        .map(|i| convert_bit_local::<F, Gf40Bit>(ctx.role(), i, &xor_share))
        .collect::<Vec<_>>()
}

async fn convert_triples_to_shares<F, C, S>(
    ctx: C,
    record_id: RecordId,
    triples: &[BitConversionTriple<S>],
) -> Result<Vec<S>, Error>
where
    F: Field,
    C: Context,
    S: LinearSecretSharing<F> + SecureMul<C>,
{
    let futures = triples.iter().enumerate().map(|(i, t)| {
        let c = ctx.narrow(&BitOpStep::from(i));
        async move { convert_bit(c, record_id, t).await }
    });

    try_join_all(futures).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    ConvertShares,
    UpgradeBitTriples,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::ConvertShares => "convert_shares",
            Self::UpgradeBitTriples => "upgrade_bit_triples",
        }
    }
}
