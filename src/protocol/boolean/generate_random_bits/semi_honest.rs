use super::{convert_triples_to_shares, random_bits_triples, RandomBits, Step};
use crate::{
    error::Error,
    ff::PrimeField,
    protocol::{
        context::{Context, SemiHonestContext},
        RecordId,
    },
    secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
};
use async_trait::async_trait;

#[async_trait]
impl<F: PrimeField> RandomBits<F> for SemiHonestContext<'_> {
    type Share = Replicated<F>;

    /// Generates a sequence of `l` random bit sharings in the target field `F`.
    async fn generate_random_bits(self, record_id: RecordId) -> Result<Vec<Self::Share>, Error> {
        let triples = random_bits_triples(&self, record_id);

        convert_triples_to_shares(self.narrow(&Step::ConvertShares), record_id, &triples).await
    }
}
