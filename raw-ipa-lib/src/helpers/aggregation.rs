#![allow(clippy::module_name_repetitions)]

#[cfg(feature = "enable-serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct PublicAggregationHelper {}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct AggregationHelper {
    #[serde(flatten)]
    public: PublicAggregationHelper,
}
