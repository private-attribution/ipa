use super::bitwise_less_than_prime::BitwiseLessThanPrime;
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::{context::Context, RecordId};
use crate::secret_sharing::replicated::malicious::{
    AdditiveShare as MaliciousReplicated, DowngradeMalicious, UnauthorizedDowngradeWrapper,
};
use crate::secret_sharing::{Arithmetic as ArithmeticSecretSharing, SecretSharing};
use async_trait::async_trait;
use std::marker::PhantomData;

#[derive(Debug)]
pub struct RandomBitsShare<F, S>
where
    F: Field,
    S: SecretSharing<F>,
{
    pub b_b: Vec<S>,
    pub b_p: S,
    _marker: PhantomData<F>,
}

#[async_trait]
impl<F> DowngradeMalicious for RandomBitsShare<F, MaliciousReplicated<F>>
where
    F: Field,
{
    type Target =
        RandomBitsShare<F, crate::secret_sharing::replicated::semi_honest::AdditiveShare<F>>;

    async fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target> {
        use crate::secret_sharing::replicated::malicious::ThisCodeIsAuthorizedToDowngradeFromMalicious;

        // Note that this clones the values rather than moving them.
        // This code is only used in test code, so that's probably OK.
        assert!(cfg!(test), "This code isn't ideal outside of tests");
        UnauthorizedDowngradeWrapper::new(Self::Target {
            b_b: self
                .b_b
                .iter()
                .map(|v| v.x().access_without_downgrade().clone())
                .collect::<Vec<_>>(),
            b_p: self.b_p.x().access_without_downgrade().clone(),
            _marker: PhantomData,
        })
    }
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

// Try generating random sharing of bits, `[b]_B`, and `l`-bit long.
// Each bit has a 50% chance of being a 0 or 1, so there are
// `F::Integer::MAX - p` cases where `b` may become larger than `p`.
// However, we calculate the number of bits needed to form a random
// number that has the same number of bits as the prime.
// With `Fp32BitPrime` (prime is `2^32 - 5`), that chance is around
// 1 * 10^-9. For Fp31, the chance is 1 out of 32 =~ 3%.
pub async fn solved_bits<F, S, C>(
    ctx: C,
    record_id: RecordId,
) -> Result<Option<RandomBitsShare<F, S>>, Error>
where
    F: Field,
    S: ArithmeticSecretSharing<F>,
    C: Context<F, Share = S>,
{
    //
    // step 1 & 2
    //
    let b_b = ctx
        .narrow(&Step::RandomBits)
        .generate_random_bits(record_id)
        .await?;

    //
    // step 3, 4 & 5
    //
    // if b >= p, then abort by returning `None`
    if !is_less_than_p(ctx.clone(), record_id, &b_b).await? {
        return Ok(None);
    }

    //
    // step 6
    //
    // if success, then compute `[b_p]` by `Σ 2^i * [b_i]_B`
    #[allow(clippy::cast_possible_truncation)]
    let b_p: S = b_b
        .iter()
        .enumerate()
        .fold(S::ZERO, |acc, (i, x)| acc + &(x.clone() * F::from(1 << i)));

    Ok(Some(RandomBitsShare {
        b_b,
        b_p,
        _marker: PhantomData,
    }))
}

async fn is_less_than_p<F, C, S>(ctx: C, record_id: RecordId, b_b: &[S]) -> Result<bool, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: ArithmeticSecretSharing<F>,
{
    let c_b =
        BitwiseLessThanPrime::less_than_prime(ctx.narrow(&Step::IsPLessThanB), record_id, b_b)
            .await?;
    if ctx.narrow(&Step::RevealC).reveal(record_id, &c_b).await? == F::ZERO {
        return Ok(false);
    }
    Ok(true)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    RandomBits,
    IsPLessThanB,
    RevealC,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::RandomBits => "random_bits",
            Self::IsPLessThanB => "is_p_less_than_b",
            Self::RevealC => "reveal_c",
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use crate::protocol::boolean::solved_bits::solved_bits;
    use crate::secret_sharing::SharedValue;
    use crate::test_fixture::Runner;
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime},
        protocol::{context::Context, RecordId},
        test_fixture::{bits_to_value, Reconstruct, TestWorld},
    };
    use rand::{distributions::Standard, prelude::Distribution};
    use std::iter::zip;

    /// Execute `solved_bits` `COUNT` times for `F`. The count should be chosen
    /// such that the probability of that many consecutive failures in `F` is
    /// negligible (less than 2^-100).
    async fn random_bits<F: Field, const COUNT: usize>()
    where
        Standard: Distribution<F>,
    {
        let world = TestWorld::new().await;
        let [rv0, rv1, rv2] = world
            .semi_honest((), |ctx, ()| async move {
                let mut outputs = Vec::with_capacity(COUNT);
                let ctx = ctx.set_total_records(COUNT);
                for i in 0..COUNT {
                    outputs.push(solved_bits(ctx.clone(), RecordId::from(i)).await.unwrap());
                }
                outputs
            })
            .await;

        let results = zip(rv0.into_iter(), zip(rv1.into_iter(), rv2.into_iter()))
            .map(|(r0, (r1, r2))| [r0, r1, r2])
            .collect::<Vec<_>>();

        let mut successes = 0;

        for result in results {
            // if one of `SolvedBits` calls aborts, then all must have aborted, too
            if result.iter().any(Option::is_none) {
                assert!(result.iter().all(Option::is_none));
                continue; // without incrementing successes
            }

            let [s0, s1, s2] = result.map(Option::unwrap);

            // [b]_B must be the same bit lengths
            assert_eq!(s0.b_b.len(), s1.b_b.len());
            assert_eq!(s1.b_b.len(), s2.b_b.len());

            // Reconstruct b_B from ([b_1]_p,...,[b_l]_p) bitwise sharings in F_p
            let b_b = (0..s0.b_b.len())
                .map(|i| {
                    let bit = [&s0.b_b[i], &s1.b_b[i], &s2.b_b[i]].reconstruct();
                    assert!(bit == F::ZERO || bit == F::ONE);
                    bit
                })
                .collect::<Vec<_>>();

            // Reconstruct b_P
            let b_p = [&s0.b_p, &s1.b_p, &s2.b_p].reconstruct();

            // Base10 of `b_B ⊆ Z` must equal `b_P`
            assert_eq!(b_p.as_u128(), bits_to_value(&b_b));

            successes += 1;
        }

        assert!(successes > 0);
    }

    #[tokio::test]
    pub async fn fp31() {
        // Probability of failure for one iteration is 2^-5.
        // Need 21 runs to reduce failure to < 2^-100.
        random_bits::<Fp31, 21>().await;
    }

    #[tokio::test]
    pub async fn fp_32bit_prime() {
        // Probability of failure for one iteration is 5/2^32 =~ 2^-30.
        // Need 4 runs to reduce failure to < 2^-100.
        random_bits::<Fp32BitPrime, 4>().await;
    }

    #[tokio::test]
    pub async fn malicious() {
        let world = TestWorld::new().await;
        let mut success = 0;

        for _ in 0..4 {
            let results = world
                .malicious(Fp32BitPrime::ZERO, |ctx, share_of_zero| async move {
                    let share_option = solved_bits(ctx.set_total_records(1), RecordId::from(0))
                        .await
                        .unwrap();
                    match share_option {
                        None => {
                            // This is a 5 in 4B case where `solved_bits()`
                            // generated a random number > prime.
                            //
                            // `malicious()` requires its closure to return `Downgrade`
                            // so we indicate the abort case with (0, [0]), instead
                            // of (0, [0, 32]). But this isn't ideal because we can't
                            // catch a bug where solved_bits returns a 1-bit random bits
                            // of 0.
                            (share_of_zero.clone(), vec![share_of_zero.clone()])
                        }
                        Some(share) => (share.b_p, share.b_b),
                    }
                })
                .await;

            let [result0, result1, result2] = results;
            let ((s0, v0), (s1, v1), (s2, v2)) = (result0, result1, result2);

            // bit lengths must be the same
            assert_eq!(v0.len(), v1.len());
            assert_eq!(v0.len(), v2.len());

            let s = [s0, s1, s2].reconstruct();
            let v = zip(v0, zip(v1, v2))
                .map(|(b0, (b1, b2))| {
                    let bit = [b0, b1, b2].reconstruct();
                    assert!(bit == Fp32BitPrime::ZERO || bit == Fp32BitPrime::ONE);
                    bit
                })
                .collect::<Vec<_>>();

            if v.len() > 1 {
                // Base10 of `b_B ⊆ Z` must equal `b_P`
                assert_eq!(s.as_u128(), bits_to_value(&v));
                success += 1;
            }
        }
        // The chance of this protocol aborting 4 out of 4 tries in Fp32BitPrime
        // is about 2^-100. Assert that at least one run has succeeded.
        assert!(success > 0);
    }
}
