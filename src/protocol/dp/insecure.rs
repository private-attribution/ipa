#![allow(dead_code)]

use crate::protocol::dp::distributions::{BoxMuller, Float};
use rand::distributions::Distribution;
use rand_core::{CryptoRng, RngCore};
use std::ops::Range;

#[derive(Debug, thiserror::Error)]
pub enum Error<F: Float> {
    #[error("Epsilon value must be greater than {0}, got {1}")]
    BadEpsilon(F, F),
    #[error("Valid values for DP-delta are within {0}, got: {1}")]
    BadDelta(Range<F>, F),
}

/// Applies DP to the inputs in the clear using smooth Laplacian noise. Works with floats only, so
/// any trimming on values must be done outside. IPA values (breakdown keys fit into `u32`)
/// are representable by both `f32` and `f64` types, so cast is not lossy.
/// It also makes it a bit easier to test if values expected to follow normal distribution.
///
/// It is not intended to be used inside IPA protocol, only for testing purposes
#[derive(Debug)]
pub struct Dp<F: Float> {
    normal_dist: BoxMuller<F>,
}

impl<F: Float> Dp<F> {

    /// ## Errors
    /// If epsilon or delta is negative or delta exceeds the maximum value allowed.
    pub fn new(epsilon: F, delta: F, cap: F) -> Result<Self, Error<F>> {
        // make sure delta and epsilon are in range, i.e. >min and delta<1-min
        if epsilon < F::MIN_POSITIVE {
            return Err(Error::BadEpsilon(F::MIN_POSITIVE, epsilon));
        }

        if delta < F::MIN_POSITIVE || delta > F::ONE - F::MIN_POSITIVE {
            return Err(Error::BadDelta(
                F::MIN_POSITIVE..F::ONE - F::MIN_POSITIVE,
                delta,
            ));
        }

        // for (eps, delta) DP, the variance needs to be sensitivity^2/(eps^2) * 2ln(1.25/delta) see https://arxiv.org/pdf/1702.07476.pdf page 2
        // sensitivity=L2(max(output_(with user x) - output_(without user x)))=sqrt(breakdown_count * user_contribution_per_breakdown^2)<cap
        // minimum eps, delta is 1/u64_max, max for delta is 1-min
        let variance = (cap / epsilon) * F::sqrt(F::from(2.0) * F::ln(F::from(1.25_f32) / delta));

        Ok(Self {
            normal_dist: BoxMuller {
                mean: F::ZERO,
                std: variance,
            },
        })
    }

    fn apply<I, R>(&self, mut input: I, rng: &mut R)
    where
        R: RngCore + CryptoRng,
        I: AsMut<[F]>,
    {
        for v in input.as_mut() {
            let sample = self.normal_dist.sample(rng);
            *v = *v + sample;
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::protocol::dp::distributions::close;
    use proptest::{prelude::ProptestConfig, proptest};
    use rand::{rngs::StdRng, thread_rng, Rng};
    use rand_core::SeedableRng;

    #[test]
    fn dp_normal_distribution_generation_standard() {
        let delta = 1.25_f64 * ((1_f64 / std::f64::consts::E).sqrt());
        let dp = Dp::new(1.0, delta, 1.0).unwrap();
        assert!(close(dp.normal_dist.mean, 0_f64, 2) && close(dp.normal_dist.std, 1_f64, 2));
    }

    #[test]
    fn dp_bad_epsilon() {
        let e = Dp::new(-1.0, 0.5, 1.0).unwrap_err();
        assert!(matches!(e, Error::BadEpsilon(_, _)));
    }

    #[test]
    fn dp_bad_delta() {
        let e = Dp::new(1.0, -1.0, 1.0).unwrap_err();
        assert!(matches!(e, Error::BadDelta(_, _)));

        let e = Dp::new(1.0, 2.0, 1.0).unwrap_err();
        assert!(matches!(e, Error::BadDelta(_, _)));
    }

    #[test]
    fn dp_normal_distribution_generation_random() {
        let mut rng = thread_rng();
        let cap: u32 = rng.gen();
        let delta: f64 = rng.gen_range(1e-9..1e-6);
        let epsilon: f64 = f64::from(rand::random::<u8>());
        let sensitivity = f64::from(cap);
        let dp = Dp::new(epsilon, delta, sensitivity).unwrap();
        let s = (sensitivity) / (epsilon) * ((2_f64 * (1.25_f64.ln() - delta.ln())).sqrt());
        assert!(dp.normal_dist.mean.abs() < f64::EPSILON);
        assert!((dp.normal_dist.std - s).abs() < f64::EPSILON);
    }

    #[test]
    fn dp_normal_distribution_apply() {
        follows_normal_distribution(118, 42, 1, 1e-9);
    }

    fn follows_normal_distribution(seed: u64, cap: u8, epsilon: u8, delta: f64) {
        const N: usize = 10000;
        // The sample_variance from a Gaussian distribution follows a chi square distribution with
        // bounds:
        // LB = (n - 1) * std^2 / chi2inv(alpha/2,n - 1)
        // UB = (n - 1) * std^2 / chi2inv(1 - alpha/2, n - 1)
        // where N is the size of the sample, alpha - the probability of any value to be outside
        // of the expected distribution range. For the purpose of this test, alpha is set to 0.01,
        // chi2inv(0.9999,10,000 - 1) = 10,535
        // chi2inv(0.0001,10,000 - 1) = 9,482.6
        // if the dataset size changes, those values need to be recomputed
        const CHI2_INV_LB: f64 = 9_482.6;
        const CHI2_INV_UB: f64 = 10_535.0;

        let mut rng = StdRng::seed_from_u64(seed);
        let mut sample = [0_f64; N];
        let dp = Dp::new(f64::from(epsilon), delta, f64::from(cap)).unwrap();
        #[allow(clippy::cast_precision_loss)]
        let n = N as f64;

        dp.apply(&mut sample, &mut rng);
        // infer mean and variance according to
        // https://en.wikipedia.org/wiki/Normal_distribution#Statistical_inference
        let sample_mean = sample.iter().sum::<f64>() / n;
        let sample_variance = sample
            .iter()
            .map(|i| (i - sample_mean).powi(2))
            .sum::<f64>()
            / (n - 1.0);
        let distribution = dp.normal_dist.std.powi(2);
        let lower = (n - 1.0) * distribution / CHI2_INV_UB;
        let upper = (n - 1.0) * distribution / CHI2_INV_LB;

        assert!(
            lower <= sample_variance && sample_variance <= upper,
            "{lower} <= {sample_variance} <= {upper} invariant does not hold"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]
        #[test]
        fn output_differentially_private(
            rng_seed: u64,
            epsilon in 1..255_u8,
            delta in 1e-9..1e-6,
            cap in 1..255_u8) {
            follows_normal_distribution(rng_seed, cap, epsilon, delta);
        }
    }
}
