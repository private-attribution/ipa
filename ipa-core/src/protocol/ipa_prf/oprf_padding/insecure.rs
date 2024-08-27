#![allow(dead_code)]

use std::f64::consts::E;

use rand::distributions::{BernoulliError, Distribution};
use rand_core::{CryptoRng, RngCore};

use crate::protocol::ipa_prf::oprf_padding::distributions::{
    BoxMuller, RoundedBoxMuller, TruncatedDoubleGeometric,
};

pub type DpError = Error;

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("Epsilon value must be greater than {}, got {0}", f64::MIN_POSITIVE)]
    BadEpsilon(f64),
    #[error("Valid values for DP-delta are within {:?}, got: {0}", f64::MIN_POSITIVE..1.0 - f64::MIN_POSITIVE)]
    BadDelta(f64),
    #[error(
        "Valid values for TruncatedDoubleGeometric are greater than {:?}, got: {0}",
        f64::MIN_POSITIVE
    )]
    BadS(f64),
    #[error(
        "Valid values for success probability in Geometric are greater than {:?}, got: {0}",
        f64::MIN_POSITIVE
    )]
    BadGeometricProb(f64),
    #[error(
        "Shift value over 1M -- likely don't need it that large and preventing to avoid any chance of overflow
        in Double Geometric sample",
    )]
    BadShiftValue(u32),
    #[error(
        "Sensitivity value over 1M -- likely don't need it that large and preventing to avoid any chance of overflow
        in Double Geometric sample",
    )]
    BadSensitivity(u32),
}
impl From<BernoulliError> for Error {
    fn from(_: BernoulliError) -> Self {
        Error::BadGeometricProb(f64::NAN)
    }
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

///  Non-negative DP noise for OPRF padding
///  Samples from a Truncated Double Geometric
#[derive(Debug, PartialEq)]
pub struct OPRFPaddingDp {
    epsilon: f64,
    delta: f64,
    sensitivity: u32, // $\Delta$
    truncated_double_geometric: TruncatedDoubleGeometric,
}
fn pow_u32(mut base: f64, mut exp: u32) -> f64 {
    // To avoid type precision loss, we implemented pow for a u32 exponent
    // like the algorithm here https://docs.rs/num-traits/0.2.15/src/num_traits/pow.rs.html#189
    if exp == 0 {
        return 1.0;
    }

    while exp & 1 == 0 {
        base = base * base;
        exp >>= 1;
    }
    if exp == 1 {
        return base;
    }

    let mut acc = base;
    while exp > 1 {
        exp >>= 1;
        base = base * base;
        if exp & 1 == 1 {
            acc *= base;
        }
    }
    acc
}

fn right_hand_side(n: u32, big_delta: u32, epsilon: f64) -> f64 {
    // Computes the right hand side of equation (11) in https://arxiv.org/pdf/2110.08177.pdf
    let r = E.powf(-epsilon);
    let a = (1.0 - r) / (1.0 + r - 2.0 * (pow_u32(r, n + 1)));
    let mut result = 0.0;
    for k in n - big_delta + 1..=n {
        result += pow_u32(r, k);
    }
    a * result
}
fn find_smallest_n(big_delta: u32, epsilon: f64, small_delta: f64) -> u32 {
    // for a fixed set of DP parameters, finds the smallest n that satisfies equation (11)
    // of https://arxiv.org/pdf/2110.08177.pdf.  This gives the narrowest TruncatedDoubleGeometric
    // that will satisfy the desired DP parameters.
    for n in big_delta.. {
        if small_delta >= right_hand_side(n, big_delta, epsilon) {
            return n;
        }
    }
    panic!("No smallest n found for OPRF padding DP");
}

impl OPRFPaddingDp {
    // See dp/README.md
    /// # Errors
    /// will return errors if invalid DP parameters are provided.
    pub fn new(new_epsilon: f64, new_delta: f64, new_sensitivity: u32) -> Result<Self, Error> {
        // make sure delta and epsilon are in range, i.e. >min and delta<1-min
        if new_epsilon < f64::MIN_POSITIVE {
            return Err(Error::BadEpsilon(new_epsilon));
        }

        if !(f64::MIN_POSITIVE..=1.0 - f64::MIN_POSITIVE).contains(&new_delta) {
            return Err(Error::BadDelta(new_delta));
        }
        if new_sensitivity > 1_000_000 {
            return Err(Error::BadSensitivity(new_sensitivity));
        }

        // compute the smallest shift needed to achieve this delta
        let smallest_n = find_smallest_n(new_sensitivity, new_epsilon, new_delta);

        Ok(Self {
            epsilon: new_epsilon,
            delta: new_delta,
            sensitivity: new_sensitivity,
            truncated_double_geometric: TruncatedDoubleGeometric::new(
                1.0 / new_epsilon,
                smallest_n,
            )?,
        })
    }

    /// Generates a sample from the `OPRFPaddingDp` struct.
    pub fn sample<R: RngCore + CryptoRng>(&self, rng: &mut R) -> u32 {
        self.truncated_double_geometric.sample(rng)
    }

    /// Returns the mean and an upper bound on the standard deviation of the `OPRFPaddingDp` distribution
    /// The upper bound is valid if the standard deviation is greater than 1.
    /// see `oprf_padding/README.md`
    #[must_use]
    pub fn mean_and_std_bound(&self) -> (f64, f64) {
        let mean = f64::from(self.truncated_double_geometric.shift_doubled) / 2.0;
        let s = 1.0 / self.epsilon;
        let p = 1.0 - E.powf(-1.0 / s);
        let std_bound = (2.0 * (1.0 - p) / pow_u32(p, 2)).sqrt();
        (mean, std_bound)
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use std::collections::BTreeMap;

    use proptest::{prelude::ProptestConfig, proptest};
    use rand::{rngs::StdRng, thread_rng, Rng};
    use rand_core::SeedableRng;

    use super::*;
    use crate::protocol::ipa_prf::oprf_padding::distributions::is_close;

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

    /// Tests for OPRF Padding DP
    #[test]
    fn test_pow_u32() {
        assert!(is_close(pow_u32(2.0, 4), 16.0, 5));
        assert!(is_close(pow_u32(6.0, 3), 216.0, 5));
        assert!(is_close(pow_u32(0.0, 0), 1.0, 5));
    }

    #[test]
    fn test_find_smallest_n() {
        assert_eq!(find_smallest_n(1, 0.5, 1e-6), 25);
        assert_eq!(find_smallest_n(1, 1.0, 1e-06), 14);
        assert_eq!(find_smallest_n(1, 0.1, 1e-06), 109);
        assert_eq!(find_smallest_n(1, 0.01, 1e-06), 852);
        assert_eq!(find_smallest_n(1, 1.0, 1e-07), 16);
        assert_eq!(find_smallest_n(1, 0.1, 1e-07), 132);
        assert_eq!(find_smallest_n(1, 0.01, 1e-07), 1082);
        assert_eq!(find_smallest_n(1, 1.0, 1e-08), 18);
        assert_eq!(find_smallest_n(1, 0.1, 1e-08), 155);
        assert_eq!(find_smallest_n(1, 0.01, 1e-08), 1313);
        assert_eq!(find_smallest_n(10, 1.0, 1e-06), 23);
        assert_eq!(find_smallest_n(10, 0.1, 1e-06), 137);
        assert_eq!(find_smallest_n(10, 0.01, 1e-06), 1087);
        assert_eq!(find_smallest_n(10, 1.0, 1e-07), 25);
        assert_eq!(find_smallest_n(10, 0.1, 1e-07), 160);
        assert_eq!(find_smallest_n(10, 0.01, 1e-07), 1317);
        assert_eq!(find_smallest_n(10, 1.0, 1e-08), 28);
        assert_eq!(find_smallest_n(10, 0.1, 1e-08), 183);
        assert_eq!(find_smallest_n(10, 0.01, 1e-08), 1548);
        assert_eq!(find_smallest_n(100, 1.0, 1e-06), 113);
        assert_eq!(find_smallest_n(100, 0.1, 1e-06), 231);
        assert_eq!(find_smallest_n(100, 0.01, 1e-06), 1366);
        assert_eq!(find_smallest_n(100, 1.0, 1e-07), 115);
        assert_eq!(find_smallest_n(100, 0.1, 1e-07), 254);
        assert_eq!(find_smallest_n(100, 0.01, 1e-07), 1597);
        assert_eq!(find_smallest_n(100, 1.0, 1e-08), 118);
        assert_eq!(find_smallest_n(100, 0.1, 1e-08), 277);
        assert_eq!(find_smallest_n(100, 0.01, 1e-08), 1827);
        assert_eq!(find_smallest_n(1000, 1.0, 1e-06), 1013);
        assert_eq!(find_smallest_n(1000, 0.1, 1e-06), 1131);
        assert_eq!(find_smallest_n(1000, 0.01, 1e-06), 2312);
        assert_eq!(find_smallest_n(1000, 1.0, 1e-07), 1015);
        assert_eq!(find_smallest_n(1000, 0.1, 1e-07), 1154);
        assert_eq!(find_smallest_n(1000, 0.01, 1e-07), 2542);
        assert_eq!(find_smallest_n(1000, 1.0, 1e-08), 1018);
        assert_eq!(find_smallest_n(1000, 0.1, 1e-08), 1177);
        assert_eq!(find_smallest_n(1000, 0.01, 1e-08), 2773);
    }
    #[test]
    fn test_oprf_padding_dp() {
        let oprf_padding = OPRFPaddingDp::new(1.0, 1e-6, 10).unwrap();

        let mut rng = rand::thread_rng();

        let num_samples = 1000;
        let mut count_sample_values: BTreeMap<u32, u32> = BTreeMap::new();

        for _ in 0..num_samples {
            let sample = oprf_padding.sample(&mut rng);
            let sample_count = count_sample_values.entry(sample).or_insert(0);
            *sample_count += 1;
        }
        for (sample, count) in &count_sample_values {
            println!("A sample value equal to {sample} occurred {count} time(s)",);
        }
    }
    fn test_oprf_padding_dp_constructor() {
        let mut actual = OPRFPaddingDp::new(-1.0, 1e-6, 10); // (epsilon, delta, sensitivity)
        let mut expected = Err(Error::BadEpsilon(-1.0));
        assert_eq!(expected, Ok(actual));
        actual = OPRFPaddingDp::new(1.0, -1e-6, 10); // (epsilon, delta, sensitivity)
        expected = Err(Error::BadDelta(-1e-6));
        assert_eq!(expected, Ok(actual));
        actual = OPRFPaddingDp::new(1.0, -1e-6, 1_000_001); // (epsilon, delta, sensitivity)
        expected = Err(Error::BadSensitivity(1_000_001));
        assert_eq!(expected, Ok(actual));
    }
}
