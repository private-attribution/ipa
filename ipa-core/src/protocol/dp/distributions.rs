use std::{
    f64::{consts::{E, PI},}, fmt::Debug,};
use rand::{
    distributions::{Bernoulli, Distribution, Uniform},
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
/// Double Geometric Distribution
///
/// Generates a sample from a geometric distribution with the given success probability.
fn generate_geometric(probability: f64) -> isize {
    // Create a Bernoulli distribution with the specified success probability
    let bernoulli = Bernoulli::new(probability).expect("Invalid probability");
    // Generate Bernoulli random numbers until the first success
    let mut rng = rand::thread_rng();
    let mut attempts = 0;
    while !bernoulli.sample(&mut rng) {
        attempts += 1;
    }
    attempts
}
/// Generates a sample from a double geometric distribution with the given success probability and shift parameter.
fn generate_double_geometric(s: f64, shift: isize) -> isize {
    let success_probability = 1.0 - E.powf(-1.0 / s);
    let attempts1 = generate_geometric(success_probability);
    let attempts2 = generate_geometric(success_probability);
    (shift + attempts1 - attempts2).try_into().unwrap()
}
/// Generates a sample from a double geometric distribution with the given success probability and shift parameter.
fn generate_truncated_double_geometric(s: f64, n: isize) -> isize {
    let mut reject = 1;
    let mut sample = 0; // Declare sample here
    while reject == 1 {
        sample = generate_double_geometric(s, n); // Assign a value to sample inside the loop
        if sample >= 0 && sample <= (2 * n).try_into().unwrap() {
            reject = 0
        }
    }
    sample.try_into().unwrap() // Return the final value of sample
}
/// Truncated Double Geometric distribution.
#[derive(Debug)]
pub struct TruncatedDoubleGeometric {
    success_probability: f64,
    shift: isize,
}
impl TruncatedDoubleGeometric {
    /// Creates a new `TruncatedDoubleGeometric` distribution with the given success probability and shift parameter.
    pub fn new(success_probability: f64, shift: isize) -> Self {
        Self {
            success_probability,
            shift,
        }
    }
    /// Generates a sample from the `TruncatedDoubleGeometric` distribution.
    pub fn sample<R: Rng>(&self, rng: &mut R) -> isize {
        generate_truncated_double_geometric(self.success_probability, self.shift)
    }
}
impl Distribution<usize> for TruncatedDoubleGeometric {
    fn sample<R: Rng +Sized>(&self, rng: &mut R) -> usize {
        self.sample(rng)
    }
}
#[cfg(all(test, unit_test))]
mod tests {
    use std::{collections::HashMap, iter::repeat_with};
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


    /// Tests for Double Geometric
    ///
    #[test]
    fn test_generate_geometric_sample_dist() {
        let p = 0.5; // success probability
        let mut histogram = HashMap::new();
        let num_samples = 100000;
        for _ in 0..num_samples {
            let sample = generate_geometric(p);
            *histogram.entry(sample).or_insert(0) += 1;
        }
        for x in 0..100 {
            let observed_probability = histogram
                .get(&x)
                .map_or(0.0, |count| *count as f64 / num_samples as f64);
            let expected_probability = (1.0 - p).powf(x as f64) * p as f64;
            // println!("x = {}, Observed Probability = {}, Expected Probability = {}", x, observed_probability, expected_probability);
            assert!((observed_probability - expected_probability) <= 0.01);
        }
    }
    #[test]
    fn test_generate_truncated_double_geometric() {
        let s = 1.0;
        let n = 25;
        let mut samples = Vec::new();
        // Sample 100 values from the generate_truncated_double_geometric function
        for _ in 0..100 {
            let sample = generate_truncated_double_geometric(s, n);
            assert!(sample > 0 && sample < 2 * n);
            samples.push(sample);
        }
        // Print the samples to the console
        println!(
            "Samples from generate_truncated_geometric with s={}, n={}: {:?}",
            s, n, samples
        );
    }
    #[test]
    fn test_generate_truncated_double_geometric_hoffding() {
        assert!(test_internal_generate_truncated_double_geometric_hoffding());
    }
    fn test_internal_generate_truncated_double_geometric_hoffding() -> bool {
        let number_samples = 1000;
        let failure_prob = 1.0;
        let s = 1.0; // Set s to some value (e.g., 1.0)
        let n = 25; // Set n to some value (e.g., 25)
        let t = f64::sqrt(
            f64::powf(2.0 * (n as f64), 2.0) / (-2.0 * (number_samples as f64))
                * f64::ln(failure_prob / 2.0),
        );
        println!("t: {:?}", t);
        let mut samples = Vec::new();
        // Sample number_samples values from the generate_truncated_double_geometric function
        for _ in 0..number_samples {
            let sample = generate_truncated_double_geometric(s, n);
            samples.push(sample);
        }
        // Compute the sample mean
        let sample_mean = samples.iter().sum::<isize>() as f64 / samples.len() as f64;
        // println!("sample_mean: {:?}", sample_mean);
        // Check that the sample mean is within some distance of the expected value
        let expected_mean = n as f64;
        // println!("expected_mean: {:?}", expected_mean);
        if sample_mean >= expected_mean - (t as f64) && sample_mean <= expected_mean + (t as f64) {
            true // Return true if the test passes
        } else {
            false // Return false if the test fails
        }
    }
    #[test]
    fn test_generate_truncated_double_geometric_sample_dist() {
        let epsilon = 1.0;
        let s = 1.0 / epsilon;
        let n = 25 as isize;
        let num_samples = 100000;
        let mut samples = Vec::new();
        // Sample 1000 values from the generate_truncated_double_geometric function
        for _ in 0..num_samples {
            let sample = generate_truncated_double_geometric(s, n) as isize;
            assert!(sample >= 0 && sample <= (2 * n).try_into().unwrap());
            samples.push(sample);
        }
        // Compute the observed probability for each value in the range [0, 2*n)
        let mut histogram = HashMap::new();
        for value in samples {
            *histogram.entry(value).or_insert(0) += 1;
        }
        let mut sorted_keys: Vec<isize> = histogram.keys().cloned().collect();
        sorted_keys.sort();
        // Compute the expected probability for each value in the range [0, 2*n]
        let normalizing_factor = (1.0 - E.powf(-epsilon))
            / (1.0 + E.powf(-epsilon) - 2.0 * E.powf(-epsilon * ((n + 1) as f64))); // 'A' in paper
                                                                                                    // println!("A = {}", normalizing_factor);
                                                                                                    // Compare the observed and expected probabilities for each value in the range [0, 2*n]
        for x in 0..2 * n + 1 {
            let observed_probability = histogram
                .get(&x)
                .map_or(0.0, |count| *count as f64 / num_samples as f64);
            let expected_probability =
                normalizing_factor * E.powf(-epsilon * ((n - x).abs() as f64));
            // println!("x, prob: {}, {}",x,expected_probability);
            // println!("Value: {}, Observed Probability: {:.4}, Expected Probability: {:.4}", x, observed_probability, expected_probability);
            assert!(
                (observed_probability - expected_probability).abs() <= 0.01,
                "Observed probability is not within 1% of expected probability"
            );
        }
    }
}
