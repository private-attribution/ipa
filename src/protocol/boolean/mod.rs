use futures::future::try_join_all;

use crate::{
    error::Error,
    ff::Field,
    protocol::{basics::SecureMul, BasicProtocols},
    secret_sharing::{Arithmetic as ArithmeticSecretSharing, SecretSharing},
};
use std::iter::repeat;

use super::{basics::ShareKnownValue, context::Context, BitOpStep, RecordId};

mod bit_decomposition;
pub mod bitwise_equal;
mod bitwise_gt_constant;
mod bitwise_less_than_prime;
mod dumb_bitwise_add_constant;
mod generate_random_bits;
pub mod or;
pub mod random_bits_generator;
mod solved_bits;
mod xor;

pub use bit_decomposition::BitDecomposition;
pub use bitwise_gt_constant::bitwise_greater_than_constant;
pub use generate_random_bits::RandomBits;
pub use solved_bits::RandomBitsShare;
pub use xor::{xor, xor_sparse};

/// Converts the given number to a sequence of `{0,1} ⊆ F`, and creates a
/// local replicated share.
pub fn local_secret_shared_bits<F, C, S>(ctx: &C, x: u128) -> Vec<S>
where
    F: Field,
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
            multiplications.push(S::multiply(
                ctx.narrow(&BitOpStep::from(mult_count)),
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
    S: ArithmeticSecretSharing<F>,
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
    S: ArithmeticSecretSharing<F> + BasicProtocols<C, F>,
{
    let one = S::share_known_value(&ctx, F::ONE);
    let res = no_ones(ctx, record_id, x).await?;
    Ok(one - &res)
}

pub(crate) async fn no_ones<F, C, S>(ctx: C, record_id: RecordId, x: &[S]) -> Result<S, Error>
where
    F: Field,
    C: Context,
    S: ArithmeticSecretSharing<F> + BasicProtocols<C, F>,
{
    let one = S::share_known_value(&ctx, F::ONE);
    let inverted_elements = flip_bits(one.clone(), x);
    // To check if a list of shares are all shares of one, we just need to multiply them all together (in any order)
    multiply_all_shares(ctx, record_id, &inverted_elements).await
}
