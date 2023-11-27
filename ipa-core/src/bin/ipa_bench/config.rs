use std::ops::Range;

use serde::{Deserialize, Serialize};

#[cfg(feature = "enable-serde")]
#[derive(Serialize, Deserialize, Debug)]
pub struct WeightedIndex<T> {
    pub index: T,
    pub weight: f64,
}

#[cfg(feature = "enable-serde")]
#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub devices_per_user: Vec<WeightedIndex<u8>>,
    pub cvr_per_ad: Vec<WeightedIndex<Range<f64>>>,
    pub conversion_value_per_user: Vec<WeightedIndex<Range<u32>>>,
    pub reach_per_ad: Vec<WeightedIndex<Range<u32>>>,
    pub impression_per_user: Vec<WeightedIndex<u8>>,
    pub conversion_per_user: Vec<WeightedIndex<u8>>,
    pub impression_impression_duration: Vec<WeightedIndex<Range<f64>>>,
    pub impression_conversion_duration: Vec<WeightedIndex<Range<u32>>>,
}
