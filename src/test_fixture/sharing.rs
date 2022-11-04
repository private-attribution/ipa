use crate::ff::Field;
use crate::secret_sharing::Replicated;
use rand::Rng;
use rand::RngCore;

use super::ReplicatedShares;

/// Shares `input` into 3 replicated secret shares using the provided `rng` implementation
pub fn share<F: Field, R: RngCore>(input: F, rng: &mut R) -> [Replicated<F>; 3] {
    let x1 = F::from(rng.gen::<u128>());
    let x2 = F::from(rng.gen::<u128>());
    let x3 = input - (x1 + x2);

    [
        Replicated::new(x1, x2),
        Replicated::new(x2, x3),
        Replicated::new(x3, x1),
    ]
}

/// Validates correctness of the secret sharing scheme.
///
/// # Panics
/// Panics if the given input is not a valid replicated secret share.
pub fn validate_and_reconstruct<T: Field>(
    input: (Replicated<T>, Replicated<T>, Replicated<T>),
) -> T {
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
pub fn validate_list_of_shares<T: Field>(expected_result: &[u128], result: &ReplicatedShares<T>) {
    (0..result.0.len()).for_each(|i| {
        assert_eq!(
            validate_and_reconstruct((result.0[i], result.1[i], result.2[i])),
            T::from(expected_result[i])
        );
    });
}
