use crate::{
    error::Error,
    ff::{Field, PrimeField},
    protocol::{
        basics::{SecureMul, ShareKnownValue},
        context::Context,
        step::BitOpStep,
        BasicProtocols, RecordId,
    },
    secret_sharing::{Linear as LinearSecretSharing, SecretSharing},
};
use std::iter::repeat;

pub mod add_constant;
pub mod bit_decomposition;
pub mod bitwise_equal;
pub mod bitwise_less_than_prime;
pub mod comparison;
pub mod generate_random_bits;
pub mod or;
pub mod random_bits_generator;
pub mod solved_bits;
mod xor;

pub use bit_decomposition::BitDecomposition;
pub use comparison::greater_than_constant;
pub use generate_random_bits::random_bits;
pub use solved_bits::RandomBitsShare;
pub use xor::{xor, xor_sparse};

/// Converts the given number to a sequence of `{0,1} ⊆ F`, and creates a
/// local replicated share.
pub fn local_secret_shared_bits<F, C, S>(ctx: &C, x: u128) -> Vec<S>
where
    F: PrimeField,
    C: Context,
    S: SecretSharing<F> + ShareKnownValue<C, F>,
{
    (0..(u128::BITS - F::PRIME.into().leading_zeros()))
        .map(|i| {
            if ((x >> i) & 1) == 1 {
                S::share_known_value(ctx, F::ONE)
            } else {
                S::ZERO
            }
        })
        .collect::<Vec<_>>()
}

/// We can minimize circuit depth by doing this in a binary-tree like fashion, where pairs of shares are multiplied together
/// and those results are recursively multiplied.
pub(crate) async fn multiply_all_shares<F, C, S>(
    ctx: C,
    record_id: RecordId,
    x: &[S],
) -> Result<S, Error>
where
    F: Field,
    C: Context,
    S: SecretSharing<F> + SecureMul<C>,
{
    let mut shares_to_multiply = x.to_vec();
    let mut mult_count = 0_u32;

    while shares_to_multiply.len() > 1 {
        let half = shares_to_multiply.len() / 2;
        let mut multiplications = Vec::with_capacity(half);
        for i in 0..half {
            multiplications.push(shares_to_multiply[2 * i].multiply(
                &shares_to_multiply[2 * i + 1],
                ctx.narrow(&BitOpStep::from(mult_count)),
                record_id,
            ));
            mult_count += 1;
        }
        // This needs to happen in parallel.
        let mut results = ctx.parallel_join(multiplications).await?;
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
    S: LinearSecretSharing<F>,
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
    C: Context,
    S: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    let one = S::share_known_value(&ctx, F::ONE);
    let res = all_zeroes(ctx, record_id, x).await?;
    Ok(one - &res)
}

pub(crate) async fn all_zeroes<F, C, S>(ctx: C, record_id: RecordId, x: &[S]) -> Result<S, Error>
where
    F: Field,
    C: Context,
    S: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    let one = S::share_known_value(&ctx, F::ONE);
    let inverted_elements = flip_bits(one.clone(), x);
    // To check if a list of shares are all shares of one, we just need to multiply them all together (in any order)
    multiply_all_shares(ctx, record_id, &inverted_elements).await
}
