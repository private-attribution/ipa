use rand::{
    distributions::{uniform::SampleUniform, Distribution, Uniform},
    Rng,
};

use std::{
    fmt::Debug,
    ops::{Add, Div, Mul, Neg, Sub},
};

pub trait Float:
    PartialOrd
    + Debug
    + Copy
    + Clone
    + SampleUniform
    + Neg<Output = Self>
    + Div<Output = Self>
    + Sub<Output = Self>
    + Add<Output = Self>
    + Mul<Output = Self>
    + From<f32>
{
    const ZERO: Self;
    const ONE: Self;
    const PI: Self;
    const MIN_POSITIVE: Self;

    fn cos(self) -> Self;
    fn ln(self) -> Self;
    fn sqrt(self) -> Self;
    fn abs(self) -> Self;
    fn clamp(self, min: Self, max: Self) -> Self;
    fn max(self, other: Self) -> Self;
    fn powi(self, n: i32) -> Self;
    fn powf(self, n: Self) -> Self;
    fn log2(self) -> Self;
    fn ceil(self) -> Self;
}

#[cfg(all(test, unit_test))]
pub fn close<F: Float>(a: F, b: F, precision: u8) -> bool {
    (a - b).abs()
        < (F::from(2.0).powf((a.abs() + F::ONE).log2().ceil())
            / F::from(10.0).powi(i32::from(precision)))
}

macro_rules! std_float_impl {
    ( $( $std_type:ident )+ ) => {
        $(
            impl Float for $std_type {
                const ZERO: Self = 0.0;
                const ONE: Self = 1.0;
                const PI: Self = std::$std_type::consts::PI;
                const MIN_POSITIVE: Self = $std_type::MIN_POSITIVE;

                fn cos(self) -> Self {
                    $std_type::sin(self)
                }

                fn ln(self) -> Self {
                    $std_type::ln(self)
                }

                fn sqrt(self) -> Self {
                    $std_type::sqrt(self)
                }

                fn abs(self) -> Self {
                    $std_type::abs(self)
                }

                fn clamp(self, min: Self, max: Self) -> Self {
                    $std_type::clamp(self, min, max)
                }

                fn max(self, other: Self) -> Self {
                    $std_type::max(self, other)
                }

                fn powi(self, n: i32) -> Self {
                    $std_type::powi(self, n)
                }
                fn powf(self, n: Self) -> Self {
                    $std_type::powf(self, n)
                }
                fn log2(self) -> Self {
                    $std_type::log2(self)
                }
                fn ceil(self) -> Self {
                    $std_type::ceil(self)
                }
            }
        )+
    };
}

std_float_impl!(f32 f64);

/// Normal distribution based on [`Box-Muller`] transform.
///
/// [`Box-Muller`]: https://en.wikipedia.org/wiki/Box%E2%80%93Muller_transform
#[derive(Debug)]
pub struct BoxMuller<F>
where
    F: Float,
{
    pub mean: F,
    pub std: F,
}

impl<F> Distribution<F> for BoxMuller<F>
where
    F: Float,
{
    fn sample<R>(&self, rng: &mut R) -> F
    where
        R: ?Sized + Rng,
    {
        let ud = Uniform::new(F::ZERO, F::ONE);
        let u = ud.sample(rng);
        let v = ud.sample(rng);
        let n = F::sqrt(F::from(-2.0) * F::ln(u)) * F::cos(F::from(2.0) * F::PI * v);

        // map sample to N(mean,variance)=sqrt(variance)*sample+mean
        n * self.std + self.mean
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use super::*;
    use rand::{distributions::Distribution, thread_rng};
    use std::iter::Sum;

    fn compute_mean_and_std<F: Float + Sum, A: AsRef<[F]>>(samples: A) -> (F, F) {
        let samples = samples.as_ref();
        assert!(!samples.is_empty() && samples.len() < usize::try_from(1 << 24).unwrap());
        #[allow(clippy::cast_precision_loss)]
        // we checked that len can be represented by an f32 above
        let l = F::from(samples.len() as f32);
        let mean = samples.iter().copied().sum::<F>() / l;
        let std = (samples
            .iter()
            .copied()
            .map(|x| (x - mean).powi(2))
            .sum::<F>()
            / l)
            .sqrt();
        (mean, std)
    }

    #[test]
    fn dp_normal_distribution_sample_standard() {
        let mut rng = thread_rng();
        let nd = BoxMuller {
            mean: 0_f64,
            std: 1_f64,
        };
        let samples = (0..100_000)
            .map(|_| nd.sample(&mut rng))
            .collect::<Vec<_>>();
        let (mean, std) = compute_mean_and_std(samples);

        assert!(close(mean, 0_f64, 2));
        assert!(close(std, 1_f64, 2));
    }

    #[test]
    fn dp_normal_distribution_sample_random() {
        let mut rng = thread_rng();
        let nd = BoxMuller {
            mean: rng.gen(),
            std: rng.gen::<f64>().abs().sqrt(),
        };
        let samples = (0..100_000)
            .map(|_| nd.sample(&mut rng))
            .collect::<Vec<_>>();
        let (mean, std) = compute_mean_and_std(samples);

        assert!(close(mean, nd.mean, 2));
        assert!(close(std, nd.std, 2));
    }

    #[test]
    fn dp_normal_distribution_f32() {
        let mut rng = thread_rng();
        let nd = BoxMuller {
            mean: rng.gen(),
            std: rng.gen::<f32>().abs().sqrt(),
        };
        let samples = (0..100_000)
            .map(|_| nd.sample(&mut rng))
            .collect::<Vec<_>>();
        let (mean, std) = compute_mean_and_std(samples);

        assert!(close(mean, nd.mean, 2));
        assert!(close(std, nd.std, 2));
    }
}
