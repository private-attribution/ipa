use super::bitwise_lt::BitwiseLessThan;
use crate::error::Error;
use crate::ff::{Field, Int};
use crate::helpers::Role;
use crate::protocol::boolean::BitOpStep;
use crate::protocol::modulus_conversion::convert_shares::{ConvertShares, XorShares};
use crate::protocol::reveal::Reveal;
use crate::protocol::{context::ProtocolContext, RecordId};
use crate::secret_sharing::Replicated;
use futures::future::try_join_all;

#[allow(dead_code)]
pub struct RandomBitsShare<F: Field> {
    b_b: Vec<Replicated<F>>,
    b_p: Replicated<F>,
}

/// This protocol tries to generate a sequence of uniformly random sharing of
/// bits in `F_p`. Adding these 3-way secret-sharing will yield the secret
/// `b_i ∈ {0,1}`. This protocol will abort and returns `None` if the secret
/// number from randomly generated bits is not less than the field's prime
/// number. Once aborted, the caller must provide a new narrowed context if
/// they wish to call this protocol again for the same `record_id`.
///
/// This is an implementation of "3.1 Generating random solved BITS" from I. Damgård
/// et al., but replaces `RAN_2` with our own PRSS implementation in lieu.
///
/// 3.1 Generating random solved BITS
/// "Unconditionally Secure Constant-Rounds Multi-party Computation for Equality, Comparison, Bits, and Exponentiation"
/// I. Damgård et al.
pub struct SolvedBits {}

impl SolvedBits {
    // Try generating random sharing of bits, `[b]_B`, and `l`-bit long.
    // Each bit has a 50% chance of being a 0 or 1, so there are
    // `F::Integer::MAX - p` cases where `b` may become larger than `p`.
    // With `Fp32BitPrime` (prime is `2^32 - 5`), that chance is around
    // 1 * 10^-9. For Fp31, the chance of this protocol succeeding is around
    // 1/2^3 =~ 13% (3 high bits being all 0's).
    #[allow(dead_code)]
    pub async fn execute<F: Field>(
        ctx: ProtocolContext<'_, Replicated<F>, F>,
        record_id: RecordId,
    ) -> Result<Option<RandomBitsShare<F>>, Error> {
        //
        // step 1 & 2
        //
        let b_b = Self::generate_random_bits(ctx.clone(), record_id).await?;

        //
        // step 3, 4 & 5
        //
        // if b >= p, then abort by returning `None`
        if !Self::is_less_than_p(ctx.clone(), record_id, &b_b).await? {
            return Ok(None);
        }

        //
        // step 6
        //
        // if success, then compute `[b_p]` by `Σ 2^i * [b_i]_B`
        #[allow(clippy::cast_possible_truncation)]
        let b_p: Replicated<F> = b_b
            .iter()
            .enumerate()
            .fold(Replicated::ZERO, |acc, (i, x)| {
                acc + &(x.clone() * F::from(2_u128.pow(i as u32)))
            });

        Ok(Some(RandomBitsShare { b_b, b_p }))
    }

    /// Generates a sequence of `l` random bit sharings in the target field `F`.
    async fn generate_random_bits<F: Field>(
        ctx: ProtocolContext<'_, Replicated<F>, F>,
        record_id: RecordId,
    ) -> Result<Vec<Replicated<F>>, Error> {
        // We assume the bit length we operate in would not exceed 255
        #[allow(clippy::cast_possible_truncation)]
        let l = F::Integer::BITS as u8;

        // Generate a pair of random numbers. We'll use these numbers as
        // the source of `l`-bit long uniformly random sequence of bits.
        let (b_bits_left, b_bits_right) = ctx
            .narrow(&Step::RandomFields)
            .prss()
            .generate_values(record_id);

        // Same here. For now, 64-bit is enough for our F_p
        #[allow(clippy::cast_possible_truncation)]
        let xor_shares = XorShares::new(l, b_bits_left as u64, b_bits_right as u64);

        // Convert each bit to secret sharings of that bit in the target field
        let c = ctx.narrow(&Step::ConvertShares);
        let futures = (0..l).map(|i| {
            // again, we don't expect our prime field to be > 2^64
            #[allow(clippy::cast_possible_truncation)]
            let c = c.narrow(&BitOpStep::Step(i as usize));
            async move {
                ConvertShares::new(xor_shares)
                    .execute_one_bit(c, record_id, i as u8)
                    .await
            }
        });

        try_join_all(futures).await
    }

    async fn is_less_than_p<F: Field>(
        ctx: ProtocolContext<'_, Replicated<F>, F>,
        record_id: RecordId,
        b_b: &[Replicated<F>],
    ) -> Result<bool, Error> {
        let p_b = Self::local_secret_shared_bits_p(ctx.role());
        let c_b =
            BitwiseLessThan::execute(ctx.narrow(&Step::IsPLessThanB), record_id, b_b, &p_b).await?;
        if ctx.narrow(&Step::RevealC).reveal(record_id, &c_b).await? == F::ZERO {
            return Ok(false);
        }
        Ok(true)
    }

    /// Internal use only.
    /// Converts the prime number to a sequence of `{0,1} ⊆ F`, and creates a
    /// local replicated share.
    fn local_secret_shared_bits_p<F: Field>(helper_role: Role) -> Vec<Replicated<F>> {
        let x = F::PRIME.into();
        let l = F::Integer::BITS;
        (0..l)
            .map(|i| {
                let b = F::from((x >> i) & 1);
                match helper_role {
                    Role::H1 => Replicated::new(b, F::ZERO),
                    Role::H2 => Replicated::new(F::ZERO, F::ZERO),
                    Role::H3 => Replicated::new(F::ZERO, b),
                }
            })
            .collect::<Vec<_>>()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    RandomFields,
    ConvertShares,
    IsPLessThanB,
    RevealC,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::RandomFields => "random_fields",
            Self::ConvertShares => "convert_shares",
            Self::IsPLessThanB => "is_p_less_than_b",
            Self::RevealC => "reveal_c",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SolvedBits;
    use crate::{
        error::Error,
        ff::{Field, Fp31, Fp32BitPrime},
        protocol::{context::ProtocolContext, QueryId, RecordId},
        secret_sharing::Replicated,
        test_fixture::{
            bits_to_value, make_contexts, make_world, validate_and_reconstruct, TestWorld,
        },
    };
    use futures::future::try_join3;
    use rand::{distributions::Standard, prelude::Distribution};

    async fn random_bits<F: Field>(
        ctx: [ProtocolContext<'_, Replicated<F>, F>; 3],
        record_id: RecordId,
    ) -> Result<Option<(Vec<F>, F)>, Error>
    where
        Standard: Distribution<F>,
    {
        let [c0, c1, c2] = ctx;

        // Execute
        let (result0, result1, result2) = try_join3(
            SolvedBits::execute(c0.bind(record_id), record_id),
            SolvedBits::execute(c1.bind(record_id), record_id),
            SolvedBits::execute(c2.bind(record_id), record_id),
        )
        .await?;

        // if one of `SolvedBits` calls aborts, then all must have aborted, too
        if result0.is_none() || result1.is_none() || result2.is_none() {
            assert!(result0.is_none());
            assert!(result1.is_none());
            assert!(result2.is_none());
            return Ok(None);
        }

        let (s0, s1, s2) = (result0.unwrap(), result1.unwrap(), result2.unwrap());

        // [b]_B must be the same bit lengths
        assert_eq!(s0.b_b.len(), s1.b_b.len());
        assert_eq!(s1.b_b.len(), s2.b_b.len());

        // Reconstruct b_B from ([b_1]_p,...,[b_l]_p) bitwise sharings in F_p
        let b_b = (0..s0.b_b.len())
            .map(|i| {
                let bit = validate_and_reconstruct(&s0.b_b[i], &s1.b_b[i], &s2.b_b[i]);
                assert!(bit == F::ZERO || bit == F::ONE);
                bit
            })
            .collect::<Vec<_>>();

        // Reconstruct b_P
        let b_p = validate_and_reconstruct(&s0.b_p, &s1.b_p, &s2.b_p);

        Ok(Some((b_b, b_p)))
    }

    #[tokio::test]
    pub async fn fp31() -> Result<(), Error> {
        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts::<Fp31>(&world);
        let [c0, c1, c2] = ctx;

        // 0.012 secs per invocation. 100 tries = 1.2 secs
        for i in 0..100 {
            let record_id = RecordId::from(i);
            // The chance of this protocol aborting 100 out of 100 tries in Fp31 is < 0.0001%.
            // Should we test and see if it succeeds at least once?
            if let Some((b_b, b_p)) =
                random_bits([c0.clone(), c1.clone(), c2.clone()], record_id).await?
            {
                // Base10 of `b_B ⊆ Z` must equal `b_P`
                assert_eq!(b_p.as_u128(), bits_to_value(&b_b));
            }
        }

        Ok(())
    }

    #[tokio::test]
    pub async fn fp_32bit_prime() -> Result<(), Error> {
        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts::<Fp32BitPrime>(&world);
        let [c0, c1, c2] = ctx;

        // 0.055 secs per invocation. 20 tries = 1.1 secs
        for i in 0..20 {
            let record_id = RecordId::from(i);
            if let Some((b_b, b_p)) =
                random_bits([c0.clone(), c1.clone(), c2.clone()], record_id).await?
            {
                // Base10 of `b_B ⊆ Z` must equal `b_P`
                assert_eq!(b_p.as_u128(), bits_to_value(&b_b));
            }
        }

        Ok(())
    }
}
