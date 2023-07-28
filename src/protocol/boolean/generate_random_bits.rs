use crate::{
    error::Error,
    ff::{Field, Gf40Bit, PrimeField},
    protocol::{
        basics::SecureMul,
        context::{
            Context, UpgradableContext, UpgradedContext, UpgradedMaliciousContext,
            UpgradedSemiHonestContext,
        },
        modulus_conversion::{convert_bit, convert_bit_local, BitConversionTriple},
        prss::SharedRandomness,
        step::BitOpStep,
        RecordId,
    },
    secret_sharing::{
        replicated::{
            malicious::{AdditiveShare as MaliciousReplicated, ExtendableField},
            semi_honest::AdditiveShare as Replicated,
            ReplicatedSecretSharing,
        },
        Linear as LinearSecretSharing, SecretSharing, SharedValue,
    },
    seq_join::SeqJoin,
};
use async_trait::async_trait;
use ipa_macros::step;
use strum::AsRefStr;

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
    let xor_share = Replicated::new(
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
    ctx.parallel_join(triples.iter().enumerate().map(|(i, t)| {
        let c = ctx.narrow(&BitOpStep::from(i));
        async move { convert_bit(c, record_id, t).await }
    }))
    .await
}

#[step]
pub(crate) enum Step {
    ConvertShares,
    UpgradeBitTriples,
}

#[async_trait]
impl<C, F> RandomBits<F> for C
where
    C: UpgradableContext,
    F: PrimeField + ExtendableField,
{
    type Share = Replicated<F>;

    /// Generates a sequence of `l` random bit sharings in the target field `F`.
    async fn generate_random_bits(self, record_id: RecordId) -> Result<Vec<Self::Share>, Error> {
        let triples = random_bits_triples(&self, record_id);

        convert_triples_to_shares(self.narrow(&Step::ConvertShares), record_id, &triples).await
    }
}

#[async_trait]
impl<F> RandomBits<F> for UpgradedSemiHonestContext<'_, F>
where
    F: PrimeField + ExtendableField,
{
    type Share = Replicated<F>;

    /// Generates a sequence of `l` random bit sharings in the target field `F`.
    async fn generate_random_bits(self, record_id: RecordId) -> Result<Vec<Self::Share>, Error> {
        let triples = random_bits_triples(&self, record_id);

        convert_triples_to_shares(self.narrow(&Step::ConvertShares), record_id, &triples).await
    }
}

#[async_trait]
impl<F: PrimeField + ExtendableField> RandomBits<F> for UpgradedMaliciousContext<'_, F> {
    type Share = MaliciousReplicated<F>;

    /// Generates a sequence of `l` random bit sharings in the target field `F`.
    async fn generate_random_bits(self, record_id: RecordId) -> Result<Vec<Self::Share>, Error> {
        let triples = random_bits_triples::<F, _>(&self, record_id);

        // Upgrade the replicated shares to malicious, in parallel,
        let c = self.narrow(&Step::UpgradeBitTriples);
        let ctx = &c;
        let malicious_triples = ctx
            .parallel_join(triples.into_iter().enumerate().map(|(i, t)| async move {
                ctx.narrow(&BitOpStep::from(i))
                    .upgrade_for(record_id, t)
                    .await
            }))
            .await?;

        convert_triples_to_shares(
            self.narrow(&Step::ConvertShares),
            record_id,
            &malicious_triples,
        )
        .await
    }
}
