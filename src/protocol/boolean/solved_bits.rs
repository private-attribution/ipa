use super::bitwise_less_than_prime::BitwiseLessThanPrime;
use crate::error::Error;
use crate::ff::{Field, Int};
use crate::protocol::modulus_conversion::convert_shares::{ConvertShares, XorShares};
use crate::protocol::reveal::Reveal;
use crate::protocol::{
    context::{Context, SemiHonestContext},
    BitOpStep, RecordId,
};
use crate::secret_sharing::Replicated;
use futures::future::try_join_all;
use std::iter::repeat;

#[allow(dead_code)]
#[derive(Debug)]
pub struct RandomBitsShare<F: Field> {
    pub b_b: Vec<Replicated<F>>,
    pub b_p: Replicated<F>,
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
    // However, we calculate the number of bits needed to form a random
    // number that has the same number of bits as the prime.
    // With `Fp32BitPrime` (prime is `2^32 - 5`), that chance is around
    // 1 * 10^-9. For Fp31, the chance is 1 out of 32 =~ 3%.
    #[allow(dead_code)]
    pub async fn execute<F: Field>(
        ctx: SemiHonestContext<'_, F>,
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
        ctx: SemiHonestContext<'_, F>,
        record_id: RecordId,
    ) -> Result<Vec<Replicated<F>>, Error> {
        // Calculate the number of bits we need to form a random number that
        // has the same number of bits as the prime.
        let l = u128::BITS - F::PRIME.into().leading_zeros();
        let leading_zero_bits = F::Integer::BITS - l;

        // Generate a pair of random numbers. We'll use these numbers as
        // the source of `l`-bit long uniformly random sequence of bits.
        let (b_bits_left, b_bits_right) = ctx
            .narrow(&Step::RandomValues)
            .prss()
            .generate_values(record_id);

        // Same here. For now, 256-bit is enough for our F_p
        #[allow(clippy::cast_possible_truncation)]
        let xor_shares = XorShares::new(l as u8, b_bits_left as u64, b_bits_right as u64);

        // Convert each bit to secret sharings of that bit in the target field
        let c = ctx.narrow(&Step::ConvertShares);
        let futures = (0..l).map(|i| {
            // again, we don't expect our prime field to be > 2^64
            #[allow(clippy::cast_possible_truncation)]
            let c = c.narrow(&BitOpStep::from(i as usize));
            async move {
                #[allow(clippy::cast_possible_truncation)]
                ConvertShares::new(xor_shares)
                    .execute_one_bit(c, record_id, i as u8)
                    .await
            }
        });

        // Pad 0's at the end to return `F::Integer::BITS` long bits
        let mut b_b = try_join_all(futures).await?;
        #[allow(clippy::cast_possible_truncation)]
        b_b.append(
            &mut repeat(Replicated::ZERO)
                .take(leading_zero_bits as usize)
                .collect::<Vec<_>>(),
        );

        Ok(b_b)
    }

    async fn is_less_than_p<F: Field>(
        ctx: SemiHonestContext<'_, F>,
        record_id: RecordId,
        b_b: &[Replicated<F>],
    ) -> Result<bool, Error> {
        let c_b =
            BitwiseLessThanPrime::less_than_prime(ctx.narrow(&Step::IsPLessThanB), record_id, b_b)
                .await?;
        if ctx.narrow(&Step::RevealC).reveal(record_id, &c_b).await? == F::ZERO {
            return Ok(false);
        }
        Ok(true)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    RandomValues,
    ConvertShares,
    IsPLessThanB,
    RevealC,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::RandomValues => "random_values",
            Self::ConvertShares => "convert_shares",
            Self::IsPLessThanB => "is_p_less_than_b",
            Self::RevealC => "reveal_c",
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::SolvedBits;
    use crate::protocol::context::SemiHonestContext;
    use crate::{
        error::Error,
        ff::{Field, Fp31, Fp32BitPrime},
        protocol::{QueryId, RecordId},
        test_fixture::{bits_to_value, join3, Reconstruct, TestWorld},
    };
    use rand::{distributions::Standard, prelude::Distribution};

    async fn random_bits<F: Field>(
        ctx: [SemiHonestContext<'_, F>; 3],
        record_id: RecordId,
    ) -> Result<Option<(Vec<F>, F)>, Error>
    where
        Standard: Distribution<F>,
    {
        let [c0, c1, c2] = ctx;

        // Execute
        let [result0, result1, result2] = join3(
            SolvedBits::execute(c0, record_id),
            SolvedBits::execute(c1, record_id),
            SolvedBits::execute(c2, record_id),
        )
        .await;

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
                let bit = (&s0.b_b[i], &s1.b_b[i], &s2.b_b[i]).reconstruct();
                assert!(bit == F::ZERO || bit == F::ONE);
                bit
            })
            .collect::<Vec<_>>();

        // Reconstruct b_P
        let b_p = (&s0.b_p, &s1.b_p, &s2.b_p).reconstruct();

        Ok(Some((b_b, b_p)))
    }

    #[tokio::test]
    pub async fn fp31() -> Result<(), Error> {
        let world = TestWorld::<Fp31>::new(QueryId);
        let ctx = world.contexts();
        let [c0, c1, c2] = ctx;

        let mut success = 0;
        for i in 0..21 {
            let record_id = RecordId::from(i);
            if let Some((b_b, b_p)) =
                random_bits([c0.clone(), c1.clone(), c2.clone()], record_id).await?
            {
                // Base10 of `b_B ⊆ Z` must equal `b_P`
                assert_eq!(b_p.as_u128(), bits_to_value(&b_b));
                success += 1;
            }
        }
        // The chance of this protocol aborting 21 out of 21 tries in Fp31
        // is about 2^-100. Assert that at least one run has succeeded.
        assert!(success > 0);

        Ok(())
    }

    #[tokio::test]
    pub async fn fp_32bit_prime() -> Result<(), Error> {
        let world = TestWorld::<Fp32BitPrime>::new(QueryId);
        let ctx = world.contexts();
        let [c0, c1, c2] = ctx;

        let mut success = 0;
        for i in 0..4 {
            let record_id = RecordId::from(i);
            if let Some((b_b, b_p)) =
                random_bits([c0.clone(), c1.clone(), c2.clone()], record_id).await?
            {
                // Base10 of `b_B ⊆ Z` must equal `b_P`
                assert_eq!(b_p.as_u128(), bits_to_value(&b_b));
                success += 1;
            }
        }
        assert!(success > 0);

        Ok(())
    }
}
