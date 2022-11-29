use super::or::or;
use super::BitOpStep;
use crate::error::Error;
use crate::ff::{Field, Fp31, Fp32BitPrime};
use crate::protocol::{context::Context, RecordId};
use crate::secret_sharing::SecretSharing;
use async_trait::async_trait;
use futures::future::{try_join, try_join_all};
use std::cmp::Ordering;
use std::iter::repeat;

/// This is an implementation of Bitwise Less-Than on bitwise-shared numbers.
///
/// `BitwiseLessThan` takes inputs `[x]_B = ([x_1]_p,...,[x_l]_p)` where
/// `x_1,...,x_l ∈ {0,1} ⊆ F_p` then computes `h ∈ {0, 1} <- x <? p` where
/// `h = 1` iff `x` is less than `p`.
///
/// Note that `[a]_B` can be converted to `[a]_p` by `Σ (2^i * a_i), i=0..l`. In
/// other words, if comparing two integers, the protocol expects inputs to be in
/// the little-endian; the least-significant byte at the smallest address (0'th
/// element).
///
#[async_trait]
pub trait ComparesToPrime<F: Field, C: Context<F, Share = S>, S: SecretSharing<F>> {
    async fn greater_than_or_equal_to_prime_trimmed(
        ctx: C,
        record_id: RecordId,
        x: &[S],
    ) -> Result<S, Error>;
}

#[async_trait]
impl<C, S> ComparesToPrime<Fp31, C, S> for Fp31
where
    C: Context<Fp31, Share = S> + Send + Sync,
    S: SecretSharing<Fp31>,
{
    async fn greater_than_or_equal_to_prime_trimmed(
        ctx: C,
        record_id: RecordId,
        x: &[S],
    ) -> Result<S, Error> {
        check_if_all_ones(ctx.narrow(&Step::CheckIfAllOnes), record_id, x).await
    }
}

#[async_trait]
impl<C, S> ComparesToPrime<Fp32BitPrime, C, S> for Fp32BitPrime
where
    C: Context<Fp32BitPrime, Share = S> + Send + Sync,
    S: SecretSharing<Fp32BitPrime> + Send,
{
    async fn greater_than_or_equal_to_prime_trimmed(
        ctx: C,
        record_id: RecordId,
        x: &[S],
    ) -> Result<S, Error> {
        let c1 = ctx.narrow(&Step::CheckLeastSignificantBits);
        let c2 = ctx.narrow(&Step::CheckIfAllOnes);
        let c3 = ctx.narrow(&Step::AllOnesAndFinalBits);
        let (check_least_significant_bits, most_significant_bits_all_ones) = try_join(
            check_least_significant_bits(c1, record_id, &x[0..3]),
            check_if_all_ones(c2, record_id, &x[3..]),
        )
        .await?;
        c3.multiply(
            record_id,
            &check_least_significant_bits,
            &most_significant_bits_all_ones,
        )
        .await
    }
}

/// To check if a list of shares are all shares of one, we just need to multiply them all together (in any order)
/// We can minimize circuit depth by doing this in a binary-tree like fashion, where pairs of shares are multiplied together
/// and those results are recursively multiplied.
async fn check_if_all_ones<F, C, S>(ctx: C, record_id: RecordId, x: &[S]) -> Result<S, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    let mut todo = x.to_vec();
    let mut mult_count = 0;

    while todo.len() > 1 {
        let half = todo.len() / 2;
        let mut multiplications = Vec::with_capacity(half);
        for i in 0..half {
            multiplications.push(ctx.narrow(&BitOpStep::Step(mult_count)).multiply(
                record_id,
                &todo[2 * i],
                &todo[2 * i + 1],
            ));
            mult_count += 1;
        }
        let mut results = try_join_all(multiplications).await?;
        if todo.len() % 2 == 1 {
            results.push(todo.pop().unwrap());
        }
        todo = results;
    }
    Ok(todo[0].clone())
}

/// This is a *special case* implementation which assumes the prime is all ones except for the least significant bits which are: `[1 1 0]` (little-endian)
/// This is the case for `Fp32BitPrime`.
///
/// Assuming that all the more significant bits of the value being checked are all shares of one, Just consider the least significant three bits:
/// Assume those bits are [1 1 0] (little-endian)
/// There are only 5 numbers that are greater than or equal to the prime
/// 1.) Four of them look like [X X 1] (values of X are irrelevant)
/// 2.) The final one is exactly [1 1 0]
/// We can check if either of these conditions is true with just 3 multiplications
async fn check_least_significant_bits<F: Field, C: Context<F, Share = S>, S: SecretSharing<F>>(
    ctx: C,
    record_id: RecordId,
    x: &[S],
) -> Result<S, Error> {
    let prime = F::PRIME.into();
    debug_assert!(prime & 0b111 == 0b011);
    debug_assert!(x.len() == 3);
    let least_significant_two_bits_both_one = ctx
        .narrow(&BitOpStep::Step(0))
        .multiply(record_id, &x[0], &x[1])
        .await?;
    let pivot_bit = &x[2];
    let least_significant_three_bits_all_equal_to_prime = ctx
        .narrow(&BitOpStep::Step(1))
        .multiply(
            record_id,
            &least_significant_two_bits_both_one,
            &(ctx.share_of_one() - pivot_bit),
        )
        .await?;
    or(
        ctx.narrow(&BitOpStep::Step(2)),
        record_id,
        pivot_bit,
        &least_significant_three_bits_all_equal_to_prime,
    )
    .await
}

pub async fn less_than_prime<F, C, S>(ctx: C, record_id: RecordId, x: &[S]) -> Result<S, Error>
where
    F: Field + ComparesToPrime<F, C, S>,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    let one = ctx.share_of_one();
    let gtoe = greater_than_or_equal_to_prime(ctx, record_id, x).await?;
    Ok(one - &gtoe)
}

pub async fn greater_than_or_equal_to_prime<F, C, S>(
    ctx: C,
    record_id: RecordId,
    x: &[S],
) -> Result<S, Error>
where
    F: Field + ComparesToPrime<F, C, S>,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    let prime = F::PRIME.into();
    let l = u128::BITS - prime.leading_zeros();
    let l_as_usize = l.try_into().unwrap();
    match x.len().cmp(&l_as_usize) {
        Ordering::Greater => {
            let (leading_ones, normal_check) = try_join(
                any_ones(
                    ctx.narrow(&Step::CheckIfAnyOnes),
                    record_id,
                    &x[l_as_usize..],
                ),
                F::greater_than_or_equal_to_prime_trimmed(
                    ctx.narrow(&Step::CheckTrimmed),
                    record_id,
                    &x[0..l_as_usize],
                ),
            )
            .await?;
            or(
                ctx.narrow(&Step::LeadingOnesOrRest),
                record_id,
                &leading_ones,
                &normal_check,
            )
            .await
        }
        Ordering::Equal => {
            F::greater_than_or_equal_to_prime_trimmed(
                ctx.narrow(&Step::CheckTrimmed),
                record_id,
                x,
            )
            .await
        }
        Ordering::Less => {
            panic!();
        }
    }
}

async fn any_ones<F, C, S>(ctx: C, record_id: RecordId, x: &[S]) -> Result<S, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    let one = ctx.share_of_one();
    let inverted_elements = x
        .iter()
        .zip(repeat(one.clone()))
        .map(|(a, one)| one - a)
        .collect::<Vec<_>>();
    let res = check_if_all_ones(ctx, record_id, &inverted_elements).await?;
    Ok(one - &res)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    CheckTrimmed,
    CheckIfAnyOnes,
    LeadingOnesOrRest,
    CheckIfAllOnes,
    CheckLeastSignificantBits,
    AllOnesAndFinalBits,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::CheckTrimmed => "check_trimmed",
            Self::CheckIfAnyOnes => "check_if_any_ones",
            Self::LeadingOnesOrRest => "leading_ones_or_rest",
            Self::CheckIfAllOnes => "check_if_all_ones",
            Self::CheckLeastSignificantBits => "check_least_significant_bits",
            Self::AllOnesAndFinalBits => "final_step",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{less_than_prime, ComparesToPrime};
    use crate::protocol::context::Context;
    use crate::secret_sharing::SecretSharing;
    use crate::test_fixture::Runner;
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime},
        protocol::{QueryId, RecordId},
        test_fixture::{get_bits, Reconstruct, TestWorld},
    };
    use rand::{distributions::Standard, prelude::Distribution};

    #[tokio::test]
    pub async fn fp31() {
        let zero = Fp31::ZERO;
        let one = Fp31::ONE;

        let world = TestWorld::new(QueryId);
        let test_cases = [
            get_bits::<Fp31>(30, 5),
            get_bits::<Fp31>(30, 6),
            get_bits::<Fp31>(29, 5),
            get_bits::<Fp31>(0, 5),
            get_bits::<Fp31>(1, 5),
            get_bits::<Fp31>(3, 5),
            get_bits::<Fp31>(15, 5),
        ];
        let result = world
            .semi_honest(test_cases, |ctx, shares| async move {
                try_join_all(
                    zip(
                        repeat(ctx), 
                        test_cases_for_helper,
                    ).enumerate().map(|(i, (ctx, test_case))| async move {
                        less_than_prime(ctx, RecordId::from(i), &shares).await
                    })
                ).await?
            })
            .await;

        result.reconstruct()

        // assert_eq!(zero, bitwise_less_than_prime(get_bits::<Fp31>(31, 5)).await);
        // assert_eq!(zero, bitwise_less_than_prime(get_bits::<Fp31>(32, 6)).await);
        // assert_eq!(zero, bitwise_less_than_prime(get_bits::<Fp31>(64, 7)).await);
        // assert_eq!(zero, bitwise_less_than_prime(get_bits::<Fp31>(64, 8)).await);
        // assert_eq!(zero, bitwise_less_than_prime(get_bits::<Fp31>(128, 8)).await);
        // assert_eq!(zero, bitwise_less_than_prime(get_bits::<Fp31>(224, 8)).await);
    }

    // #[tokio::test]
    // pub async fn fp32_bit_prime() {
    //     let zero = Fp32BitPrime::ZERO;
    //     let one = Fp32BitPrime::ONE;

    //     assert_eq!(
    //         zero,
    //         bitwise_less_than_prime(Fp32BitPrime::PRIME, 32).await
    //     );
    //     assert_eq!(
    //         zero,
    //         bitwise_less_than_prime(Fp32BitPrime::PRIME + 1, 32).await
    //     );
    //     assert_eq!(
    //         zero,
    //         bitwise_less_than_prime(Fp32BitPrime::PRIME + 2, 32).await
    //     );
    //     assert_eq!(
    //         zero,
    //         bitwise_less_than_prime(Fp32BitPrime::PRIME + 3, 32).await
    //     );
    //     assert_eq!(
    //         zero,
    //         bitwise_less_than_prime(Fp32BitPrime::PRIME + 4, 32).await
    //     );
    //     assert_eq!(
    //         one,
    //         bitwise_less_than_prime(Fp32BitPrime::PRIME - 1, 32).await
    //     );
    //     assert_eq!(
    //         one,
    //         bitwise_less_than_prime(Fp32BitPrime::PRIME - 2, 32).await
    //     );
    //     assert_eq!(
    //         one,
    //         bitwise_less_than_prime(Fp32BitPrime::PRIME - 3, 32).await
    //     );
    //     assert_eq!(
    //         one,
    //         bitwise_less_than_prime(Fp32BitPrime::PRIME - 4, 32).await
    //     );
    //     assert_eq!(one, bitwise_less_than_prime(0, 32).await);
    //     assert_eq!(one, bitwise_less_than_prime(1, 32).await);
    //     assert_eq!(
    //         one,
    //         bitwise_less_than_prime(65_536_u32, 32).await
    //     );
    //     assert_eq!(
    //         one,
    //         bitwise_less_than_prime(65_535_u32, 32).await
    //     );
    // }

    async fn bitwise_less_than_prime<F, C, S>(bits: Vec<F>) -> F
    where
        F: Field + ComparesToPrime<F, C, S>,
        C: Context<F, Share = S>,
        S: SecretSharing<F>,
        Standard: Distribution<F>,
    {
        let world = TestWorld::new(QueryId);
        let result = world
            .semi_honest(bits, |ctx, x_share| async move {
                less_than_prime(ctx, RecordId::from(0), &x_share)
                    .await
                    .unwrap()
            })
            .await;

        result.reconstruct()
    }
}
