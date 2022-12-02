use futures::future::try_join_all;

use crate::error::Error;
use crate::ff::{Field, Int};
use crate::secret_sharing::SecretSharing;
use std::iter::repeat;

use super::context::Context;
use super::{BitOpStep, RecordId};

mod bit_decomposition;
pub mod bitwise_equal;
mod bitwise_less_than_prime;
mod dumb_bitwise_lt;
mod dumb_bitwise_sum;
mod or;
pub mod random_bits_generator;
mod solved_bits;

pub use {bit_decomposition::BitDecomposition, dumb_bitwise_lt::BitwiseLessThan};

/// Converts the given number to a sequence of `{0,1} ⊆ F`, and creates a
/// local replicated share.
pub fn local_secret_shared_bits<F, C, S>(ctx: &C, x: u128) -> Vec<S>
where
    F: Field,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    (0..F::Integer::BITS)
        .map(|i| {
            if ((x >> i) & 1) == 1 {
                ctx.share_of_one()
            } else {
                S::ZERO
            }
        })
        .collect::<Vec<_>>()
}

/// Aligns the bits by padding extra zeros at the end (assuming the bits are in
/// little-endian format).
/// TODO: this needs to be removed; where it is used there are better optimizations.
fn align_bit_lengths<F, S>(a: &[S], b: &[S]) -> (Vec<S>, Vec<S>)
where
    F: Field,
    S: SecretSharing<F>,
{
    let mut a = a.to_vec();
    let mut b = b.to_vec();

    if a.len() == b.len() {
        return (a, b);
    }

    let pad_a = b.len().saturating_sub(a.len());
    let pad_b = a.len().saturating_sub(b.len());
    a.append(&mut repeat(S::ZERO).take(pad_a).collect::<Vec<_>>());
    b.append(&mut repeat(S::ZERO).take(pad_b).collect::<Vec<_>>());

    (a, b)
}

/// To check if a list of shares are all shares of one, we just need to multiply them all together (in any order)
/// We can minimize circuit depth by doing this in a binary-tree like fashion, where pairs of shares are multiplied together
/// and those results are recursively multiplied.
pub(crate) async fn check_if_all_ones<F, C, S>(
    ctx: C,
    record_id: RecordId,
    x: &[S],
) -> Result<S, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    let mut shares_to_multiply = x.to_vec();
    let mut mult_count = 0_u32;

    while shares_to_multiply.len() > 1 {
        let half = shares_to_multiply.len() / 2;
        let mut multiplications = Vec::with_capacity(half);
        for i in 0..half {
            multiplications.push(ctx.narrow(&BitOpStep::from(mult_count)).multiply(
                record_id,
                &shares_to_multiply[2 * i],
                &shares_to_multiply[2 * i + 1],
            ));
            mult_count += 1;
        }
        let mut results = try_join_all(multiplications).await?;
        if shares_to_multiply.len() % 2 == 1 {
            results.push(shares_to_multiply.pop().unwrap());
        }
        shares_to_multiply = results;
    }
    Ok(shares_to_multiply[0].clone())
}

fn flip_bits<F, S>(one: S, x: &[S]) -> Vec<S>
where
    F: Field,
    S: SecretSharing<F>,
{
    x.iter()
        .zip(repeat(one))
        .map(|(a, one)| one - a)
        .collect::<Vec<_>>()
}

/// # Errors
/// This does multiplications which can have errors
pub(crate) async fn any_ones<F, C, S>(ctx: C, record_id: RecordId, x: &[S]) -> Result<S, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    let one = ctx.share_of_one();
    let res = no_ones(ctx, record_id, x).await?;
    Ok(one - &res)
}

pub(crate) async fn no_ones<F, C, S>(ctx: C, record_id: RecordId, x: &[S]) -> Result<S, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    let one = ctx.share_of_one();
    let inverted_elements = flip_bits(one.clone(), x);
    check_if_all_ones(ctx, record_id, &inverted_elements).await
}

/// Secure XOR protocol with two inputs, `a, b ∈ {0,1} ⊆ F_p`.
/// It computes `[a] + [b] - 2[ab]`
///
/// # Errors
/// This does multiplications - which can error
pub async fn xor<F, C, S>(ctx: C, record_id: RecordId, a: &S, b: &S) -> Result<S, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    let ab = ctx.multiply(record_id, a, b).await?;
    Ok(-ab * F::from(2) + a + b)
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::xor;
    use crate::{
        ff::{Field, Fp31},
        protocol::{QueryId, RecordId},
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    async fn xor_fp31(world: &TestWorld, a: Fp31, b: Fp31) -> Fp31 {
        let result = world
            .semi_honest((a, b), |ctx, (a_share, b_share)| async move {
                xor(ctx, RecordId::from(0), &a_share, &b_share)
                    .await
                    .unwrap()
            })
            .await;

        result.reconstruct()
    }

    #[tokio::test]
    pub async fn all_combinations() {
        let world = TestWorld::new(QueryId);

        assert_eq!(Fp31::ZERO, xor_fp31(&world, Fp31::ZERO, Fp31::ZERO).await);
        assert_eq!(Fp31::ONE, xor_fp31(&world, Fp31::ONE, Fp31::ZERO).await);
        assert_eq!(Fp31::ONE, xor_fp31(&world, Fp31::ZERO, Fp31::ONE).await);
        assert_eq!(Fp31::ZERO, xor_fp31(&world, Fp31::ONE, Fp31::ONE).await);
    }
}
