#![allow(dead_code)]

use std::f64;

use rand::distributions::Distribution;
use rand_core::{CryptoRng, RngCore};

use crate::protocol::dp::distributions::{BoxMuller, RoundedBoxMuller};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Epsilon value must be greater than {}, got {0}", f64::MIN_POSITIVE)]
    BadEpsilon(f64),
    #[error("Valid values for DP-delta are within {:?}, got: {0}", f64::MIN_POSITIVE..1.0 - f64::MIN_POSITIVE)]
    BadDelta(f64),
}

/// Applies DP to the inputs in the clear using continuous Gaussian noise. Works with floats only, so
/// any trimming on values must be done externally.
#[derive(Debug)]
pub struct Dp {
    normal_dist: BoxMuller,
}

impl Dp {
    /// ## Errors
    /// If epsilon or delta is negative or delta exceeds the maximum value allowed.
    pub fn new(epsilon: f64, delta: f64, cap: f64) -> Result<Self, Error> {
        // make sure delta and epsilon are in range, i.e. >min and delta<1-min
        if epsilon < f64::MIN_POSITIVE {
            return Err(Error::BadEpsilon(epsilon));
        }

        if !(f64::MIN_POSITIVE..=1.0 - f64::MIN_POSITIVE).contains(&delta) {
            return Err(Error::BadDelta(delta));
        }

        // for (eps, delta) DP, the variance needs to be sensitivity^2/(eps^2) * 2ln(1.25/delta) see https://arxiv.org/pdf/1702.07476.pdf page 2
        // sensitivity=L2(max(output_(with user x) - output_(without user x)))=sqrt(breakdown_count * user_contribution_per_breakdown^2)<cap
        // minimum eps, delta is 1/u64_max, max for delta is 1-min
        let variance = (cap / epsilon) * f64::sqrt(2.0 * f64::ln(1.25 / delta));

        Ok(Self {
            normal_dist: BoxMuller {
                mean: 0.0,
                std: variance,
            },
        })
    }

    fn apply<I, R>(&self, mut input: I, rng: &mut R)
    where
        R: RngCore + CryptoRng,
        I: AsMut<[f64]>,
    {
        for v in input.as_mut() {
            let sample = self.normal_dist.sample(rng);
            *v += sample;
        }
    }
}

/// Applies DP to the inputs in the clear using a rounded continuous Gaussian noise. Works with floats only, so
/// any trimming on values must be done externally.
#[derive(Debug)]
pub struct DiscreteDp {
    rounded_normal_dist: RoundedBoxMuller,
}

impl DiscreteDp {
    /// ## Errors
    /// If epsilon or delta is negative or delta exceeds the maximum value allowed.
    pub fn new(epsilon: f64, delta: f64, cap: f64) -> Result<Self, Error> {
        let dp = Dp::new(epsilon, delta, cap)?;

        Ok(Self {
            rounded_normal_dist: RoundedBoxMuller::from(dp.normal_dist),
        })
    }

    pub fn apply<I, R>(&self, mut input: I, rng: &mut R)
    where
        R: RngCore + CryptoRng,
        I: AsMut<[i64]>,
    {
        for v in input.as_mut() {
            #[allow(clippy::cast_possible_truncation)]
            let sample = self.rounded_normal_dist.sample(rng) as i64;
            *v = v.saturating_add(sample);
        }
    }

    #[must_use]
    pub fn mean(&self) -> f64 {
        self.rounded_normal_dist.mean()
    }

    #[must_use]
    pub fn std(&self) -> f64 {
        self.rounded_normal_dist.std()
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use proptest::{prelude::ProptestConfig, proptest};
    use rand::{rngs::StdRng, thread_rng, Rng};
    use rand_core::SeedableRng;

    use super::*;
    use crate::protocol::dp::distributions::is_close;

    #[test]
    fn dp_normal_distribution_generation_standard() {
        let delta = 1.25_f64 * ((1_f64 / std::f64::consts::E).sqrt());
        let dp = Dp::new(1.0, delta, 1.0).unwrap();
        assert!(is_close(dp.normal_dist.mean, 0_f64, 2) && is_close(dp.normal_dist.std, 1_f64, 2));
    }

    #[test]
    fn dp_bad_epsilon() {
        let e = Dp::new(-1.0, 0.5, 1.0).unwrap_err();
        assert!(matches!(e, Error::BadEpsilon(_)));
    }

    #[test]
    fn dp_bad_delta() {
        let e = Dp::new(1.0, -1.0, 1.0).unwrap_err();
        assert!(matches!(e, Error::BadDelta(_)));

        let e = Dp::new(1.0, 2.0, 1.0).unwrap_err();
        assert!(matches!(e, Error::BadDelta(_)));
    }

    #[test]
    fn dp_normal_distribution_generation_random() {
        let mut rng = thread_rng();
        let cap: u32 = rng.gen();
        let delta: f64 = rng.gen_range(1e-9..1e-6);
        let epsilon = f64::from(rng.gen_range(1..255_u8));
        let sensitivity = f64::from(cap);
        let dp = Dp::new(epsilon, delta, sensitivity).unwrap();
        let s = (sensitivity) / (epsilon) * ((2_f64 * (1.25_f64.ln() - delta.ln())).sqrt());
        assert!(
            dp.normal_dist.mean.abs() < f64::EPSILON,
            "|{}| >= {}",
            dp.normal_dist.mean,
            f64::EPSILON
        );
        assert!(is_close(dp.normal_dist.std, s, 5));
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
        // of the expected distribution range. For the purpose of this test, alpha is set to 0.00002%,
        // chi2inv(0.000001, 10000 - 1) = 9341.1
        // chi2inv(0.999999, 10000 - 1) = 10686
        // if the dataset size changes, those values need to be recomputed
        const CHI2_INV_UB: f64 = 9_341.1;
        const CHI2_INV_LB: f64 = 10_686.0;

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
        let lower = (n - 1.0) * distribution / CHI2_INV_LB;
        let upper = (n - 1.0) * distribution / CHI2_INV_UB;

        assert!(
            lower <= sample_variance && sample_variance <= upper,
            "{lower} <= {sample_variance} <= {upper} invariant does not hold, epsilon = {epsilon}"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]
        #[test]
        #[allow(clippy::ignored_unit_patterns)] // https://github.com/proptest-rs/proptest/issues/371
        fn output_differentially_private(
            rng_seed: u64,
            epsilon in 1..255_u8,
            delta in 1e-9..1e-6,
            cap in 1..255_u8) {
            follows_normal_distribution(rng_seed, cap, epsilon, delta);
        }
    }

    /// Tests for Rounded Normal
    #[test]
    fn epsilon_variance_table() {
        // manual test to print the sample variance of rounded normal vs the variance of the continuous normal
        // cargo test -- protocol::dp::insecure::test::epsilon_variance_table --nocapture
        const N: usize = 10000;
        let delta: f64 = 1e-6;
        let cap = 1_u8;

        #[allow(clippy::cast_precision_loss)]
        for epsilon in 1..11_u8 {
            let mut rng = thread_rng();
            let mut sample = [0; N];
            let dp = DiscreteDp::new(f64::from(epsilon), delta, f64::from(cap)).unwrap();
            let n = N as f64;
            dp.apply(&mut sample, &mut rng);
            let sample_mean = sample.iter().sum::<i64>() as f64 / n;
            let sample_variance = sample
                .iter()
                .map(|&i| (i as f64 - sample_mean).powi(2))
                .sum::<f64>()
                / (n - 1.0);

            println!(
                "epsilon = {}, rounded_normal_sample_variance = {}, continuous_variance = {}",
                epsilon,
                sample_variance,
                dp.rounded_normal_dist.std().powi(2)
            );
            assert!(f64::abs(sample_variance - dp.rounded_normal_dist.std().powi(2)) < 2.0);
        }
    }
}
