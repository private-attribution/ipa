use std::collections::{BTreeMap, HashMap};
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use clap::Args;
use rand::rngs::StdRng;
use rand::thread_rng;
use rand_core::SeedableRng;
use crate::protocol::dp::InsecureDiscreteDp;

#[derive(Debug, Args)]
#[clap(about = "Apply differential privacy noise to the given input")]
pub struct ApplyDpArgs {
    #[arg(long, short = 'e')]
    epsilon: Vec<f64>,

    #[arg(long, short = 's')]
    seed: Option<u64>,

    #[arg(long, short = 'd', default_value = "1e-7")]
    delta: f64,

    #[arg(long, short = 'c')]
    cap: u32,
}

#[derive(Debug)]
#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NoisedOutput {
    /// Aggregated breakdowns with noise applied. It is important to use unsigned values here
    /// to avoid bias/mean skew
    pub breakdowns: Box<[i64]>,
    pub mean: f64,
    pub std: f64
}

#[derive(Debug, Copy, Clone, PartialOrd)]
pub struct EpsilonBits(f64);

#[cfg(feature = "enable-serde")]
impl serde::Serialize for EpsilonBits {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl Hash for EpsilonBits {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.0.to_ne_bytes())
    }
}

impl PartialEq for EpsilonBits {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bits().eq(&other.0.to_bits())
    }
}

impl Eq for EpsilonBits {

}

impl From<f64> for EpsilonBits {
    fn from(value: f64) -> Self {
        assert!(value.is_finite());
        Self(value)
    }
}

impl Ord for EpsilonBits {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // ok, because we reject NaN values inside `From<f64>` implementation
        self.partial_cmp(other).unwrap()
    }
}

impl Display for EpsilonBits {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

pub fn apply<I: AsRef<[u32]>>(input: I, args: ApplyDpArgs) -> BTreeMap<EpsilonBits, NoisedOutput> {
    let mut rng = args.seed.map(StdRng::seed_from_u64).unwrap_or_else(StdRng::from_entropy);
    let mut result = BTreeMap::new();
    for epsilon in args.epsilon {
        let discrete_dp = InsecureDiscreteDp::new(epsilon, args.delta, args.cap as f64).unwrap();
        let mut v = input.as_ref().iter().copied().map(i64::from).collect::<Vec<_>>();
        discrete_dp.apply(v.as_mut_slice(), &mut rng);
        result.insert(epsilon.into(), NoisedOutput {
            breakdowns: v.into_boxed_slice(),
            mean: discrete_dp.mean(),
            std: discrete_dp.std(),
        });
    }

    result
}