use crate::ff::Field;
use crate::secret_sharing::{MaliciousReplicated, Replicated};
use rand::{
    distributions::{Distribution, Standard},
    Rng, RngCore,
};

use super::ReplicatedShares;

/// Shares `input` into 3 replicated secret shares using the provided `rng` implementation
pub fn share<F: Field, R: RngCore>(input: F, rng: &mut R) -> [Replicated<F>; 3]
where
    Standard: Distribution<F>,
{
    let x1 = rng.gen::<F>();
    let x2 = rng.gen::<F>();
    let x3 = input - (x1 + x2);

    [
        Replicated::new(x1, x2),
        Replicated::new(x2, x3),
        Replicated::new(x3, x1),
    ]
}

/// Shares `input` into 3 maliciously secure replicated secret shares using the provided `rng` implementation
///
#[allow(clippy::missing_panics_doc)]
pub fn share_malicious<F: Field, R: RngCore>(x: F, rng: &mut R) -> [MaliciousReplicated<F>; 3]
where
    Standard: Distribution<F>,
{
    let rx = rng.gen::<F>() * x;
    share(x, rng)
        // TODO: array::zip/each_ref when stable
        .iter()
        .zip(share(rx, rng))
        .map(|(x, rx)| MaliciousReplicated::new(*x, rx))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// Validates correctness of the secret sharing scheme.
///
/// # Panics
/// Panics if the given input is not a valid replicated secret share.
pub fn validate_and_reconstruct<F: Field>(
    input: (Replicated<F>, Replicated<F>, Replicated<F>),
) -> F {
    assert_eq!(
        input.0.left() + input.1.left() + input.2.left(),
        input.0.right() + input.1.right() + input.2.right()
    );

    assert_eq!(input.0.right(), input.1.left());
    assert_eq!(input.1.right(), input.2.left());
    assert_eq!(input.2.right(), input.0.left());

    input.0.left() + input.1.left() + input.2.left()
}

/// Validates expected result from the secret shares obtained.
///
/// # Panics
/// Panics if the expected result is not same as obtained result. Also panics if `validate_and_reconstruct` fails
pub fn validate_list_of_shares<F: Field>(expected_result: &[u128], result: &ReplicatedShares<F>) {
    let revealed_values: Vec<F> = (0..result.0.len())
        .map(|i| validate_and_reconstruct((result.0[i], result.1[i], result.2[i])))
        .collect();

    for i in 0..revealed_values.len() {
        assert_eq!(revealed_values[i], F::from(expected_result[i]));
    }
}
