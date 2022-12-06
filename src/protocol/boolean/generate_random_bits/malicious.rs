use super::{convert_triples_to_shares, random_bits_triples, RandomBits, Step};
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::context::MaliciousContext;
use crate::protocol::{context::Context, BitOpStep, RecordId};
use crate::secret_sharing::MaliciousReplicated;
use async_trait::async_trait;
use futures::future::try_join_all;

#[async_trait]
impl<F: Field> RandomBits<F> for MaliciousContext<'_, F> {
    type Share = MaliciousReplicated<F>;

    /// Generates a sequence of `l` random bit sharings in the target field `F`.
    async fn generate_random_bits(self, record_id: RecordId) -> Result<Vec<Self::Share>, Error> {
        let triples = random_bits_triples(&self, record_id);

        // upgrade the replicated shares to malicious
        let c = self.narrow(&Step::UpgradeBitTriples);
        let malicious_triples = try_join_all(triples.into_iter().enumerate().map(|(i, t)| {
            let c = c.narrow(&BitOpStep::from(i));
            async move {
                c.upgrade_bit_triple(record_id, u32::try_from(i).unwrap(), t)
                    .await
            }
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
