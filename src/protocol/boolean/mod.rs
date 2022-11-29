use crate::ff::{Field, Int};
use crate::secret_sharing::SecretSharing;
use std::iter::repeat;

use super::context::Context;

mod bit_decomposition;
mod bitwise_less_than_prime;
mod bitwise_lt;
mod bitwise_sum;
mod carries;
mod dumb_bitwise_lt;
mod dumb_bitwise_sum;
mod or;
mod prefix_or;
pub mod random_bits_generator;
mod solved_bits;
mod xor;

/// Internal use only.
/// Converts the given number to a sequence of `{0,1} ⊆ F`, and creates a
/// local replicated share.
fn local_secret_shared_bits<F, C, S>(ctx: &C, x: u128) -> Vec<S>
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
                S::default()
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
