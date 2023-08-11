use std::{f64::consts::PI, fmt::Debug};

use rand::{
    distributions::{Distribution, Uniform},
    Rng,
};

/// Returns `true` iff `a` and `b` are close to each other. `a` and `b` are considered close if
/// |a-b| < 10^(-precision).
#[cfg(all(test, unit_test))]
pub fn is_close(a: f64, b: f64, precision: u8) -> bool {
    (a - b).abs()
        < (2.0_f64.powf((a.abs() + 1.0).log2().ceil()) / 10.0_f64.powi(i32::from(precision)))
}

/// Normal distribution based on [`Box-Muller`] transform.
///
/// [`Box-Muller`]: https://en.wikipedia.org/wiki/Box%E2%80%93Muller_transform
#[derive(Debug)]
pub struct BoxMuller {
    pub mean: f64,
    pub std: f64,
}

impl Distribution<f64> for BoxMuller {
    fn sample<R>(&self, rng: &mut R) -> f64
    where
        R: ?Sized + Rng,
    {
        let ud = Uniform::new(0.0, 1.0);
        let u = ud.sample(rng);
        let v = ud.sample(rng);
        let n = f64::sqrt(-2.0 * f64::ln(u)) * f64::cos(2.0 * PI * v);

        // map sample to N(mean,variance)=sqrt(variance)*sample+mean
        n * self.std + self.mean
    }
}

/// Rounded Normal distribution based on [`Box-Muller`] transform.
///
/// [`Box-Muller`]: https://en.wikipedia.org/wiki/Box%E2%80%93Muller_transform
#[derive(Debug)]
pub struct RoundedBoxMuller {
    inner: BoxMuller,
}

impl RoundedBoxMuller {
    pub fn std(&self) -> f64 {
        self.inner.std
    }

    pub fn mean(&self) -> f64 {
        self.inner.mean
    }
}

impl Distribution<f64> for RoundedBoxMuller {
    fn sample<R>(&self, rng: &mut R) -> f64
    where
        R: ?Sized + Rng,
    {
        self.inner.sample(rng).round()
    }
}

impl From<BoxMuller> for RoundedBoxMuller {
    fn from(value: BoxMuller) -> Self {
        Self { inner: value }
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::iter::repeat_with;

    use rand::{distributions::Distribution, thread_rng};
    use rand_core::RngCore;

    use super::*;

    #[test]
    fn dp_normal_distribution_sample_standard() {
        let mut rng = thread_rng();
        let nd = BoxMuller {
            mean: 0_f64,
            std: 1_f64,
        };

        check(&nd, &mut rng, 2_u8);
    }

    #[test]
    fn dp_normal_distribution_sample_random() {
        let mut rng = thread_rng();
        let nd = BoxMuller {
            mean: rng.gen(),
            std: rng.gen::<f64>().abs().sqrt(),
        };

        check(&nd, &mut rng, 2_u8);
    }

    fn check<R: RngCore>(nd: &BoxMuller, mut rng: &mut R, precision: u8) {
        let n = 100_000;
        #[allow(clippy::cast_precision_loss)]
        let variance = f64::sqrt(
            repeat_with(|| nd.sample(&mut rng))
                .take(n)
                .map(|x| (x - nd.mean).powi(2))
                .sum::<f64>()
                / n as f64,
        );

        assert!(is_close(variance, nd.std, precision));
    }

    /// Tests for Rounded Normal distribution
    #[test]
    fn dp_rounded_normal_distribution_sample_random() {
        let mut rng = thread_rng();
        let nd = BoxMuller {
            mean: rng.gen(),
            std: rng.gen::<f64>().abs().sqrt(),
        };
        check(&nd, &mut rng, 1_u8);
    }
}
