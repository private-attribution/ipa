use crate::ff::{Field, Int};
use crate::helpers::Role;
use crate::secret_sharing::Replicated;
use std::iter::repeat;

mod bit_decomposition;
mod bitwise_lt;
mod bitwise_sum;
mod carries;
mod or;
mod prefix_or;
mod random_bits_generator;
mod solved_bits;
mod xor;

/// A step generator for bitwise secure operations.
///
/// For each record, we decompose a value into bits (i.e. credits in the
/// Attribution protocol), and execute some binary operations like OR'ing each
/// bit. For each bitwise secure computation, we need to "narrow" the context
/// with a new step to make sure we are using an unique PRSS.
///
/// This is a temporary solution for narrowing contexts until the infra is
/// updated with a new step scheme.
enum BitOpStep {
    Step(usize),
}

impl crate::protocol::Substep for BitOpStep {}

impl AsRef<str> for BitOpStep {
    fn as_ref(&self) -> &str {
        const BIT_OP: [&str; 64] = [
            "bit0", "bit1", "bit2", "bit3", "bit4", "bit5", "bit6", "bit7", "bit8", "bit9",
            "bit10", "bit11", "bit12", "bit13", "bit14", "bit15", "bit16", "bit17", "bit18",
            "bit19", "bit20", "bit21", "bit22", "bit23", "bit24", "bit25", "bit26", "bit27",
            "bit28", "bit29", "bit30", "bit31", "bit32", "bit33", "bit34", "bit35", "bit36",
            "bit37", "bit38", "bit39", "bit40", "bit41", "bit42", "bit43", "bit44", "bit45",
            "bit46", "bit47", "bit48", "bit49", "bit50", "bit51", "bit52", "bit53", "bit54",
            "bit55", "bit56", "bit57", "bit58", "bit59", "bit60", "bit61", "bit62", "bit63",
        ];
        match self {
            Self::Step(i) => BIT_OP[*i],
        }
    }
}

/// Internal use only.
/// Converts the given number to a sequence of `{0,1} ⊆ F`, and creates a
/// local replicated share.
fn local_secret_shared_bits<F: Field>(x: u128, helper_role: Role) -> Vec<Replicated<F>> {
    // let x = F::PRIME.into();
    (0..F::Integer::BITS)
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

/// Aligns the bits by padding extra zeros at the end (assuming the bits are in
/// little-endian format).
fn align_bit_lengths<F: Field>(
    a: &[Replicated<F>],
    b: &[Replicated<F>],
) -> (Vec<Replicated<F>>, Vec<Replicated<F>>) {
    let mut a = a.to_vec();
    let mut b = b.to_vec();

    if a.len() == b.len() {
        return (a, b);
    }

    let pad_a = b.len().saturating_sub(a.len());
    let pad_b = a.len().saturating_sub(b.len());
    a.append(&mut repeat(Replicated::ZERO).take(pad_a).collect::<Vec<_>>());
    b.append(&mut repeat(Replicated::ZERO).take(pad_b).collect::<Vec<_>>());

    (a, b)
}
