use crate::secret_sharing::Field;
use crate::secret_sharing::Replicated;
use rand::Rng;
use rand::RngCore;

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
        input.0.as_tuple().0 + input.1.as_tuple().0 + input.2.as_tuple().0,
        input.0.as_tuple().1 + input.1.as_tuple().1 + input.2.as_tuple().1
    );

    assert_eq!(input.0.as_tuple().1, input.1.as_tuple().0);
    assert_eq!(input.1.as_tuple().1, input.2.as_tuple().0);
    assert_eq!(input.2.as_tuple().1, input.0.as_tuple().0);

    input.0.as_tuple().0 + input.1.as_tuple().0 + input.2.as_tuple().0
}
