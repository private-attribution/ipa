use std::iter::zip;

use crate::ff::{Field, Int};
use crate::secret_sharing::{MaliciousReplicated, Replicated};
use rand::thread_rng;
use rand::{
    distributions::{Distribution, Standard},
    Rng, RngCore,
};

use super::{MaliciousShares, ReplicatedShares};

pub trait IntoShares<S>: Sized {
    fn share(self) -> [S; 3] {
        self.share_with(&mut thread_rng())
    }
    fn share_with<R: Rng>(self, rng: &mut R) -> [S; 3];
}

impl<F> IntoShares<Replicated<F>> for F
where
    F: Field,
    Standard: Distribution<F>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [Replicated<F>; 3] {
        share(self, rng)
    }
}

impl<F> IntoShares<(Replicated<F>, Replicated<F>)> for (F, F)
where
    F: Field,
    Standard: Distribution<F>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [(Replicated<F>, Replicated<F>); 3] {
        let [x0, x1, x2] = share(self.0, rng);
        let [y0, y1, y2] = share(self.1, rng);
        [(x0, y0), (x1, y1), (x2, y2)]
    }
}

impl<F> IntoShares<(Replicated<F>, Replicated<F>, Replicated<F>)> for (F, F, F)
where
    F: Field,
    Standard: Distribution<F>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [(Replicated<F>, Replicated<F>, Replicated<F>); 3] {
        let [x0, x1, x2] = share(self.0, rng);
        let [y0, y1, y2] = share(self.1, rng);
        let [z0, z1, z2] = share(self.2, rng);
        [(x0, y0, z0), (x1, y1, z1), (x2, y2, z2)]
    }
}

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
pub fn share_malicious<F: Field, R: RngCore>(x: F, r: F, rng: &mut R) -> [MaliciousReplicated<F>; 3]
where
    Standard: Distribution<F>,
{
    zip(share(x, rng), share(r * x, rng))
        .map(|(x, rx)| MaliciousReplicated::new(x, rx))
        // TODO: array::zip/each_ref when stable
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// Take a field value `x` and turn them into replicated bitwise sharings of three
pub fn shared_bits<F: Field, R: RngCore>(x: F, rand: &mut R) -> Vec<[Replicated<F>; 3]>
where
    Standard: Distribution<F>,
{
    let x = x.as_u128();
    (0..F::Integer::BITS)
        .map(|i| share(F::from((x >> i) & 1), rand))
        .collect::<Vec<_>>()
}

/// Validates correctness of the secret sharing scheme.
///
/// # Panics
/// Panics if the given input is not a valid replicated secret share.
pub fn validate_and_reconstruct<F: Field>(
    s0: &Replicated<F>,
    s1: &Replicated<F>,
    s2: &Replicated<F>,
) -> F {
    assert_eq!(
        s0.left() + s1.left() + s2.left(),
        s0.right() + s1.right() + s2.right()
    );

    assert_eq!(s0.right(), s1.left());
    assert_eq!(s1.right(), s2.left());
    assert_eq!(s2.right(), s0.left());

    s0.left() + s1.left() + s2.left()
}

/// Validates correctness of the secret sharing scheme.
///
/// # Panics
/// Panics if the given input is not a valid replicated secret share.
pub fn validate_and_reconstruct_malicious<F: Field>(
    r: F,
    s0: &MaliciousReplicated<F>,
    s1: &MaliciousReplicated<F>,
    s2: &MaliciousReplicated<F>,
    expected_result: Option<u128>,
) -> F {
    let result = validate_and_reconstruct(s0.x(), s1.x(), s2.x());
    let result_macs = validate_and_reconstruct(s0.rx(), s1.rx(), s2.rx());

    if let Some(expected_result) = expected_result {
        assert_eq!(result, F::from(expected_result));
        assert_eq!(result_macs, F::from(expected_result) * r);
    }

    s0.x().left() + s1.x().left() + s2.x().left()
}

/// Validates expected result from the secret shares obtained.
///
/// # Panics
/// Panics if the expected result is not same as obtained result. Also panics if `validate_and_reconstruct` fails
pub fn validate_list_of_shares<F: Field>(expected_result: &[u128], result: &ReplicatedShares<F>) {
    assert_eq!(expected_result.len(), result[0].len());
    assert_eq!(expected_result.len(), result[1].len());
    assert_eq!(expected_result.len(), result[2].len());
    for (i, expected) in expected_result.iter().enumerate() {
        let revealed = validate_and_reconstruct(&result[0][i], &result[1][i], &result[2][i]);
        assert_eq!(revealed, F::from(*expected));
    }
}

/// Validates expected result from the secret shares obtained.
///
/// # Panics
/// Panics if the expected result is not same as obtained result. Also panics if `validate_and_reconstruct` fails for input or MACs
pub fn validate_list_of_shares_malicious<F: Field>(
    r: F,
    expected_result: &[u128],
    result: &MaliciousShares<F>,
) {
    assert_eq!(expected_result.len(), result[0].len());
    assert_eq!(expected_result.len(), result[1].len());
    assert_eq!(expected_result.len(), result[2].len());
    for (i, expected) in expected_result.iter().enumerate() {
        let revealed = validate_and_reconstruct_malicious(
            r,
            &result[0][i],
            &result[1][i],
            &result[2][i],
            Some(*expected),
        );
        assert_eq!(revealed, F::from(*expected));
    }
}
