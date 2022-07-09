//!
//! This module contains the implementation of [`Shamir secret sharing`] using finite fields.
//! It uses FF implementations provided by [`ff`] crate and is mostly useful when working with
//! prime fields as they support arithmetic addition and multiplication of shares that is used
//! to implement secure multiplication protocol.
//!
//! [`Shamir secret sharing`](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
//! [`ff`](https://crates.io/crates/ff)
//!
use ff::{Field, PrimeField};
use rand_core::RngCore;
use std::iter::repeat_with;
use std::num::NonZeroU8;
use std::ops::Add;
use thiserror::Error;

/// Interpolating polynomial used to reconstruct secrets encoded with Shamir secret scheme.
pub struct LagrangePolynomial<F> {
    coefficients: Vec<F>,
}

impl<F: PrimeField> LagrangePolynomial<F> {
    /// Constructs new polynomial of a given degree.
    ///
    /// ## Errors
    /// Returns an error if it fails to evaluate at least one of the coefficients
    pub fn new(degree: NonZeroU8) -> Result<Self, Error> {
        let mut coefficients = Vec::with_capacity(degree.get() as usize);
        let n = degree.get();
        for i in 1..=n {
            let mut x = F::one();
            let mut denom = F::one();

            for j in 1..=n {
                if i != j {
                    let x_i = F::from(u64::from(i));
                    let x_j = F::from(u64::from(j));
                    x *= x_j;
                    denom *= x_j - x_i;
                }
            }

            let maybe_denom = denom.invert();
            if maybe_denom.is_none().into() {
                return Err(Error::InvertError {
                    v: Box::from(denom.to_repr().as_ref()),
                });
            }
            coefficients.push(x * maybe_denom.unwrap());
        }

        Ok(Self { coefficients })
    }

    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn degree(&self) -> u8 {
        // SAFETY: new() does not allow constructing more than u8::MAX coefficients
        self.coefficients.len() as u8
    }

    // Evaluates P(0) using the first N points provided, ignoring extra points, if any.
    fn evaluate_at_zero<T: Clone + Into<F>>(&self, points: &[T]) -> F {
        points
            .iter()
            .zip(self.coefficients.iter())
            .map(|(y, &x)| y.clone().into() * x)
            .fold(F::zero(), |lhs, rhs| lhs + rhs)
    }
}

/// Shamir secret sharing
pub struct SecretSharing {
    /// Threshold
    k: u8,

    /// Number of shares produced by the `share` method
    n: u8,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Wrong or insecure secret sharing scheme. (expected {k} >= {n} > 1)")]
    BadSharingScheme { k: u8, n: u8 },
    #[error("The degree of polynomial provided to reconstruct secret does not match number of points provided. \
     Polynomial degree: {polynomial_degree}, number of points {points_count}")]
    BadPolynomial {
        polynomial_degree: u8,
        points_count: u8,
    },
    #[error("Prime field element inversion failed: {v:?}")]
    InvertError { v: Box<[u8]> },
}

/// Represents a single share: f(x) point. The index of it inside the share slice is used to represent
/// the "x" coordinate of this share.
#[derive(Clone)]
pub struct Share<F> {
    y: F,
}

impl SecretSharing {
    /// Constructs a new instance, returning `ShamirError` if input values do not allow
    /// to construct a valid Shamir secret sharing scheme.
    ///
    /// # Errors
    /// Rejects the following inputs:
    /// * k == 1
    /// * k > n
    pub fn new(k: NonZeroU8, n: NonZeroU8) -> Result<Self, Error> {
        if k.get() == 1 || k > n {
            Err(Error::BadSharingScheme {
                k: k.get(),
                n: n.get(),
            })
        } else {
            Ok(Self {
                k: k.get(),
                n: n.get(),
            })
        }
    }

    /// Minimum number of shares required to reconstruct a secret
    #[must_use]
    pub fn threshold(&self) -> u8 {
        self.k
    }

    /// Consumes and splits a given secret into `n` shares. only `k` <= `n` shares is required
    /// to reconstruct it later
    pub fn split<R: RngCore, F: PrimeField>(&self, secret: F, rng: R) -> Vec<Share<F>> {
        // generate polynomial of k-1 degree
        let coefficients = Self::gen_polynomial::<R, F>(rng)
            .take(usize::from(self.k - 1))
            .collect::<Vec<_>>();

        let mut shares = Vec::with_capacity(self.n as usize);

        // sample n points by evaluating the polynomial
        for i in 1..=self.n {
            let mut y = F::zero();
            let x = F::from(u64::from(i));
            for c in coefficients.iter().rev() {
                y += *c;
                y *= x;
            }

            y += secret;

            shares.push(Share { y });
        }

        shares
    }

    /// Reconstructs a secret from a set of size at least k of shares.
    ///
    /// # Errors
    /// Returns an error if there is no enough shares to reconstruct the secret or
    /// if an error occurred while evaluating the polynomial
    pub fn reconstruct<F>(shares: &[Share<F>], lagrange: &LagrangePolynomial<F>) -> Result<F, Error>
    where
        F: PrimeField + From<Share<F>>,
    {
        // this check is actually stricter than we need: shares.len() >= lagrange.len() is enough
        // to reconstruct (ignore extra shares). The reason why it is here is specific to IPA protocol -
        // we should not attempt to reconstruct secrets with more than n or less than n shares.
        if shares.len() != lagrange.degree() as usize {
            // SAFETY: len() fits into u8
            #[allow(clippy::cast_possible_truncation)]
            return Err(Error::BadPolynomial {
                polynomial_degree: lagrange.degree(),
                points_count: shares.len() as u8,
            });
        }

        let r = lagrange.evaluate_at_zero(shares);

        Ok(r)
    }

    /// Generate coefficients (sampled at random) for an arbitrary polynomial of infinite degree.
    fn gen_polynomial<R: RngCore, F: Field>(mut rng: R) -> impl Iterator<Item = F> {
        repeat_with(move || F::random(&mut rng))
    }
}

impl<F: Field> Add for &Share<F> {
    type Output = Share<F>;

    fn add(self, rhs: Self) -> Self::Output {
        Share { y: self.y + rhs.y }
    }
}

#[cfg(test)]
// PrimeField macro panics if this attribute is added to `Fp` struct.
#[allow(clippy::expl_impl_clone_on_copy)]
mod tests {
    use crate::shamir::{Error, LagrangePolynomial, SecretSharing, Share};
    use ff::PrimeField;
    use proptest::prelude::*;
    use rand::rngs::StdRng;
    use rand::thread_rng;
    use rand_core::SeedableRng;
    use std::cmp::max;
    use std::num::NonZeroU8;

    use rand::rngs::mock::StepRng;

    // Mersenne prime 2^61-1
    const PRIME: u64 = 2_305_843_009_213_693_951;

    #[derive(PrimeField)]
    #[PrimeFieldModulus = "2305843009213693951"]
    #[PrimeFieldGenerator = "7"]
    #[PrimeFieldReprEndianness = "little"]
    struct Fp([u64; 1]);

    impl Fp {
        pub const fn modulus() -> u64 {
            PRIME
        }
    }

    impl From<Share<Fp>> for Fp {
        fn from(share: Share<Fp>) -> Self {
            share.y
        }
    }

    #[test]
    fn can_share_8_byte_int() {
        let mut rng = StepRng::new(1, 1);
        for k in [2_u8, 5, 10, 254] {
            for n in k..=k.checked_add(5).unwrap_or(u8::MAX) {
                let k = NonZeroU8::new(k).unwrap();
                let n = NonZeroU8::new(n).unwrap();
                let lc = LagrangePolynomial::<Fp>::new(n).unwrap();
                let shamir = SecretSharing::new(k, n).unwrap();
                let secret = Fp::from(213);
                let shares = shamir.split(secret, &mut rng);

                assert_eq!(secret, SecretSharing::reconstruct(&shares, &lc).unwrap());
            }
        }
    }

    #[test]
    fn can_add_shares() {
        fn check_addition(
            shamir: &SecretSharing,
            lc: &LagrangePolynomial<Fp>,
            lhs_secret: u64,
            rhs_secret: u64,
        ) {
            let mut rng = StepRng::new(1, 1);

            let lhs_secret = Fp::from(lhs_secret);
            let rhs_secret = Fp::from(rhs_secret);
            let expected = lhs_secret + rhs_secret;

            let lhs_shares = shamir.split(lhs_secret, &mut rng);
            let rhs_shares = shamir.split(rhs_secret, &mut rng);
            let sum_shares = lhs_shares
                .iter()
                .zip(rhs_shares.iter())
                .map(|(lhs, rhs)| lhs + rhs)
                .collect::<Vec<_>>();

            let sum_secret = SecretSharing::reconstruct(&sum_shares, lc).unwrap();
            assert_eq!(expected, sum_secret);
        }

        let k = NonZeroU8::new(2).unwrap();
        let n = NonZeroU8::new(3).unwrap();
        let shamir = SecretSharing::new(k, n).unwrap();
        let lc = LagrangePolynomial::<Fp>::new(n).unwrap();

        check_addition(&shamir, &lc, 42, 24);
        check_addition(&shamir, &lc, 0, 0);
        check_addition(&shamir, &lc, Fp::modulus(), 2);
        check_addition(&shamir, &lc, 0, Fp::modulus());
    }

    #[test]
    fn fails_if_not_enough_shares() {
        let n = NonZeroU8::new(3).unwrap();
        let shamir = SecretSharing::new(NonZeroU8::new(2).unwrap(), n).unwrap();

        let shares = shamir.split(Fp::from(42), thread_rng());
        assert!(matches!(
            SecretSharing::reconstruct(&shares[0..1], &LagrangePolynomial::new(n).unwrap()),
            Err(Error::BadPolynomial {
                polynomial_degree: 3,
                points_count: 1
            })
        ));
    }

    #[test]
    fn fails_if_not_enough_coefficients() {
        let k = NonZeroU8::new(2).unwrap();
        let n = NonZeroU8::new(3).unwrap();
        let shamir = SecretSharing::new(k, n).unwrap();

        let shares = shamir.split(Fp::from(42), thread_rng());
        assert!(matches!(
            SecretSharing::reconstruct(&shares, &LagrangePolynomial::new(k).unwrap()),
            Err(Error::BadPolynomial {
                polynomial_degree: 2,
                points_count: 3
            })
        ));
    }

    #[test]
    fn can_reject_bad_k_and_n() {
        for k in [1_u8, 2, 3] {
            let n = NonZeroU8::new(max(1, k - 1)).unwrap();
            let k = NonZeroU8::new(k).unwrap();
            let r = SecretSharing::new(k, n);
            assert!(matches!(r, Err(Error::BadSharingScheme { .. })));
        }
    }

    #[test]
    fn fails_to_reconstruct_secret_with_duplicated_shares() {
        let (k, n) = (NonZeroU8::new(2).unwrap(), NonZeroU8::new(3).unwrap());
        let rng = StepRng::new(1, 1);
        let secret = Fp::from(5);

        let sharing = SecretSharing::new(k, n).unwrap();

        let mut shares = sharing.split(secret, rng);
        shares[2] = shares[1].clone();

        assert_ne!(
            secret,
            SecretSharing::reconstruct(&shares, &LagrangePolynomial::new(n).unwrap()).unwrap()
        );
    }

    #[test]
    fn fails_to_reconstruct_secret_with_forged_shares() {
        let (k, n) = (NonZeroU8::new(2).unwrap(), NonZeroU8::new(3).unwrap());
        let rng = StepRng::new(1, 1);
        let secret = Fp::from(5);

        let sharing = SecretSharing::new(k, n).unwrap();

        let mut shares = sharing.split(secret, rng);
        shares[2] = Share { y: shares[1].y };

        assert_ne!(
            secret,
            SecretSharing::reconstruct(&shares, &LagrangePolynomial::new(n).unwrap()).unwrap()
        );
    }

    //
    // Randomized tests
    //

    #[derive(Debug)]
    struct ShareReconstructInput {
        rng_seed: u64,
        k: u8,
        n: u8,
    }

    impl ShareReconstructInput {
        fn gen() -> impl Strategy<Value = Self> {
            (2u8..250)
                .prop_flat_map(|v| {
                    let k = Just(v);
                    let n = v..=255;
                    let rng_seed = any::<u64>();

                    (rng_seed, k, n)
                })
                .prop_map(|(rng_seed, k, n)| ShareReconstructInput { rng_seed, k, n })
        }
    }

    #[test]
    fn sharing_is_reversible() {
        fn can_share_and_reconstruct(
            input: &ShareReconstructInput,
            secret: u64,
        ) -> Result<(), TestCaseError> {
            let ShareReconstructInput { k, n, rng_seed } = *input;

            let k = NonZeroU8::new(k).unwrap();
            let n = NonZeroU8::new(n).unwrap();
            let r = StdRng::seed_from_u64(rng_seed);

            let shamir = SecretSharing::new(k, n).unwrap();
            let lc = LagrangePolynomial::new(n).unwrap();
            let shares = shamir.split(Fp::from(secret), r);

            let reconstructed_secret = SecretSharing::reconstruct(&shares, &lc)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;

            prop_assert_eq!(Fp::from(secret), reconstructed_secret);
            Ok(())
        }

        let test_config = if cfg!(feature = "test-harness") {
            ProptestConfig::default()
        } else {
            // to allow fast test execution while running tests locally
            ProptestConfig::with_cases(10)
        };

        proptest!(test_config, |(input in ShareReconstructInput::gen(), v in 0..PRIME)| {
            can_share_and_reconstruct(&input, v)?;
        });
    }
}
