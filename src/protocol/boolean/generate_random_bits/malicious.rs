use super::{RandomBits, Step};
use crate::error::Error;
use crate::ff::{Field, Int};
use crate::protocol::context::MaliciousContext;
use crate::protocol::modulus_conversion::{convert_bit, convert_bit_local};
use crate::protocol::{context::Context, BitOpStep, RecordId};
use crate::secret_sharing::{MaliciousReplicated, XorReplicated};
use async_trait::async_trait;
use futures::future::try_join_all;
use std::iter::repeat;

#[async_trait]
impl<F: Field> RandomBits<F> for MaliciousContext<'_, F> {
    type Share = MaliciousReplicated<F>;

    /// Generates a sequence of `l` random bit sharings in the target field `F`.
    async fn generate_random_bits(self, record_id: RecordId) -> Result<Vec<Self::Share>, Error> {
        // Calculate the number of bits we need to form a random number that
        // has the same number of bits as the prime.
        let l = u128::BITS - F::PRIME.into().leading_zeros();
        let leading_zero_bits = F::Integer::BITS - l;

        // Generate a pair of random numbers. We'll use these numbers as
        // the source of `l`-bit long uniformly random sequence of bits.
        let (b_bits_left, b_bits_right) = self
            .narrow(&Step::RandomValues)
            .prss()
            .generate_values(record_id);

        // Same here. For now, 256-bit is enough for our F_p
        let xor_share = XorReplicated::new(
            u64::try_from(b_bits_left & u128::from(u64::MAX)).unwrap(),
            u64::try_from(b_bits_right & u128::from(u64::MAX)).unwrap(),
        );

        // Convert each bit to secret sharings of that bit in the target field
        let c = self.narrow(&Step::ConvertShares);
        let futures = (0..l).map(|i| {
            let c = c.narrow(&BitOpStep::from(i));
            let triple = convert_bit_local::<F>(c.role(), i, &xor_share);
            async move {
                let malicious_triple = c.upgrade_bit_triple(record_id, i, triple).await?;
                convert_bit(c, record_id, &malicious_triple).await
            }
        });

        // Pad 0's at the end to return `F::Integer::BITS` long bits
        let mut b_b = try_join_all(futures).await?;
        b_b.append(
            &mut repeat(Self::Share::ZERO)
                .take(usize::try_from(leading_zero_bits).unwrap())
                .collect::<Vec<_>>(),
        );

        Ok(b_b)
    }
}
