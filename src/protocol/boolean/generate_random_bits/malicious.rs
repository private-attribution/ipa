use super::{convert_triples_to_shares, random_bits_triples, RandomBits, Step};
use crate::{
    error::Error,
    ff::PrimeField,
    protocol::{
        context::{Context, MaliciousContext},
        BitOpStep, RecordId,
    },
    secret_sharing::replicated::malicious::AdditiveShare as MaliciousReplicated,
};
use async_trait::async_trait;
use futures::future::try_join_all;

#[async_trait]
impl<F: PrimeField> RandomBits<F> for MaliciousContext<'_, F> {
    type Share = MaliciousReplicated<F>;

    /// Generates a sequence of `l` random bit sharings in the target field `F`.
    async fn generate_random_bits(self, record_id: RecordId) -> Result<Vec<Self::Share>, Error> {
        let triples = random_bits_triples::<F, _>(&self, record_id);

        // upgrade the replicated shares to malicious
        let c = self.narrow(&Step::UpgradeBitTriples);
        let ctx = &c;
        let malicious_triples =
            try_join_all(triples.into_iter().enumerate().map(|(i, t)| async move {
                ctx.upgrade_for_record_with(&BitOpStep::from(i), record_id, t)
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
