use std::{
    cmp::Ordering,
    collections::BTreeMap,
    fmt::{Debug, Display, Formatter},
};

use clap::Args;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize, Serializer};

use crate::protocol::dp::InsecureDiscreteDp;

#[derive(Debug, Args)]
#[clap(about = "Apply differential privacy noise to the given input")]
pub struct ApplyDpArgs {
    /// Various epsilon values to use inside the DP.
    #[arg(long, short = 'e')]
    epsilon: Vec<f64>,

    /// Delta parameter for (\epsilon, \delta) DP.
    #[arg(long, short = 'd', default_value = "1e-7")]
    delta: f64,

    /// Seed for the random number generator.
    #[arg(long, short = 's')]
    seed: Option<u64>,

    /// The sensitivity of the input or maximum contribution allowed per user to preserve privacy.
    #[arg(long, short = 'c')]
    cap: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NoisyOutput {
    /// Aggregated breakdowns with noise applied. It is important to use unsigned values here
    /// to avoid bias/mean skew
    pub breakdowns: Box<[i64]>,
    pub mean: f64,
    pub std: f64,
}

/// This exists to be able to use f64 as key inside a map. We don't have to deal with infinities or
/// NaN values for epsilons, so we can treat them as raw bytes for this purpose.
#[derive(Debug, Copy, Clone)]
pub struct EpsilonBits(f64);

impl Serialize for EpsilonBits {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl From<f64> for EpsilonBits {
    fn from(value: f64) -> Self {
        assert!(value.is_finite());
        Self(value)
    }
}

// the following implementations are fine because NaN values are rejected from inside `From<f64>`

impl PartialEq for EpsilonBits {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bits().eq(&other.0.to_bits())
    }
}

impl Eq for EpsilonBits {}

impl PartialOrd for EpsilonBits {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EpsilonBits {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.partial_cmp(&other.0).unwrap()
    }
}

impl Display for EpsilonBits {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

/// Apply DP noise to the given input.
///
/// ## Panics
/// If DP parameters are not valid.
pub fn apply<I: AsRef<[u32]>>(input: I, args: &ApplyDpArgs) -> BTreeMap<EpsilonBits, NoisyOutput> {
    let mut rng = args
        .seed
        .map_or_else(StdRng::from_entropy, StdRng::seed_from_u64);
    let mut result = BTreeMap::new();
    for &epsilon in &args.epsilon {
        let discrete_dp =
            InsecureDiscreteDp::new(epsilon, args.delta, f64::from(args.cap)).unwrap();
        let mut v = input
            .as_ref()
            .iter()
            .copied()
            .map(i64::from)
            .collect::<Vec<_>>();
        discrete_dp.apply(v.as_mut_slice(), &mut rng);

        result.insert(
            epsilon.into(),
            NoisyOutput {
                breakdowns: v.into_boxed_slice(),
                mean: discrete_dp.mean(),
                std: discrete_dp.std(),
            },
        );
    }

    result
}
