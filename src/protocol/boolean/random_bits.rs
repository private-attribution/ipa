use crate::error::BoxError;
use crate::ff::{Field, Int};
use crate::protocol::boolean::BitOpStep;
use crate::protocol::modulus_conversion::convert_shares::{ConvertShares, XorShares};
use crate::protocol::{context::ProtocolContext, RecordId};
use crate::secret_sharing::Replicated;
use futures::future::try_join_all;

/// This protocol generates a sequence of uniformly random sharing of bits in `F_p`.
/// Adding these 3-way secret-sharing will yield the secret `r_i ∈ {0,1}`.
pub struct RandomBits {}

impl RandomBits {
    #[allow(dead_code)]
    pub async fn execute<F: Field>(
        ctx: ProtocolContext<'_, Replicated<F>, F>,
        record_id: RecordId,
    ) -> Result<(Vec<Replicated<F>>, Replicated<F>), BoxError> {
        // We assume the bit length we operate in would not exceed 255
        #[allow(clippy::cast_possible_truncation)]
        let l = F::Integer::BITS as u8;

        // Generate a replicated random field values. We'll use these fields as
        // the source of `l`-bit long uniformly random sequence of bits.
        let r_p: Replicated<F> = ctx.prss().generate_replicated(record_id);

        // Convert each bit to secret sharings of that bit in the target field
        let futures = (0..l).map(|i| {
            // again, we don't expect our prime field to be > 2^64
            #[allow(clippy::cast_possible_truncation)]
            let xor_shares = XorShares {
                num_bits: l,
                packed_bits_left: r_p.left().as_u128() as u64,
                packed_bits_right: r_p.right().as_u128() as u64,
            };
            let c = ctx.narrow(&BitOpStep::Step(i as usize));
            async move {
                ConvertShares::new(xor_shares)
                    .execute_one_bit(c, record_id, i as u8)
                    .await
            }
        });
        let r_b = try_join_all(futures).await?;

        Ok((r_b, r_p))
    }
}

#[cfg(test)]
mod tests {
    use super::RandomBits;
    use crate::{
        error::BoxError,
        ff::{Field, Fp31, Fp32BitPrime},
        protocol::{QueryId, RecordId},
        test_fixture::{
            make_contexts, make_world, validate_and_reconstruct, validate_and_reconstruct_xor,
            TestWorld,
        },
    };
    use futures::future::try_join_all;
    use rand::{distributions::Standard, prelude::Distribution};

    /// Take a slice of bits in `{0,1} ⊆ F_p`, and reconstruct the integer in `F_p`
    fn bits_to_field<F: Field>(x: &[F]) -> F {
        #[allow(clippy::cast_possible_truncation)]
        let v = x
            .iter()
            .enumerate()
            .fold(0, |acc, (i, &b)| acc + 2_u128.pow(i as u32) * b.as_u128());
        F::from(v)
    }

    async fn random_bits<F: Field>() -> Result<(Vec<F>, F), BoxError>
    where
        Standard: Distribution<F>,
    {
        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts::<F>(&world);

        // Execute
        let step = "RandomBits_Test";
        let result = try_join_all(vec![
            RandomBits::execute(ctx[0].narrow(step), RecordId::from(0_u32)),
            RandomBits::execute(ctx[1].narrow(step), RecordId::from(0_u32)),
            RandomBits::execute(ctx[2].narrow(step), RecordId::from(0_u32)),
        ])
        .await
        .unwrap();

        // just renaming the results for the ease of reading
        let (r0_b, r0_p) = (result[0].0.clone(), result[0].1);
        let (r1_b, r1_p) = (result[1].0.clone(), result[1].1);
        let (r2_b, r2_p) = (result[2].0.clone(), result[2].1);

        // [r]_B must be the same bit lengths
        assert_eq!(r0_b.len(), r1_b.len());
        assert_eq!(r1_b.len(), r2_b.len());

        // Reconstruct r_B from ([r_1]_p,...,[r_l]_p) bitwise sharings in F_p
        let r_b = (0..r0_b.len())
            .map(|i| validate_and_reconstruct((r0_b[i], r1_b[i], r2_b[i])))
            .collect::<Vec<_>>();
        // [r]_p is an XOR secret sharing of `r`
        let r = validate_and_reconstruct_xor((r0_p, r1_p, r2_p));

        Ok((r_b, r))
    }

    #[tokio::test]
    pub async fn fp31() -> Result<(), BoxError> {
        for _ in 0..10 {
            let (r_b, r): (Vec<Fp31>, Fp31) = random_bits().await?;
            // Base10 of r_B must equal r
            assert_eq!(r, bits_to_field(&r_b));
        }
        Ok(())
    }

    #[tokio::test]
    pub async fn fp_32bit_prime() -> Result<(), BoxError> {
        for _ in 0..10 {
            let (r_b, r): (Vec<Fp32BitPrime>, Fp32BitPrime) = random_bits().await?;
            // Base10 of r_B must equal r
            assert_eq!(r, bits_to_field(&r_b));
        }
        Ok(())
    }
}
