use std::num::NonZeroU32;

use rand::Rng;

use super::hybrid::TestHybridRecord;

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum ConversionDistribution {
    Default,
    OnlyImpressions,
    OnlyConversions,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct Config {
    #[cfg_attr(feature = "clap", arg(long, default_value = "5"))]
    pub max_conversion_value: NonZeroU32,
    #[cfg_attr(feature = "clap", arg(long, default_value = "20"))]
    pub max_breakdown_key: NonZeroU32,
    /// Indicates the distribution of impression to conversion reports.
    #[cfg_attr(feature = "clap", arg(value_enum, long, default_value_t = ConversionDistribution::Default))]
    pub conversion_distribution: ConversionDistribution,
}

impl Default for Config {
    fn default() -> Self {
        Self::new(5, 20, ConversionDistribution::Default)
    }
}

impl Config {
    /// Creates a new instance of [`Self`]
    ///
    /// ## Panics
    /// If any argument is 0.
    #[must_use]
    pub fn new(
        max_conversion_value: u32,
        max_breakdown_key: u32,
        conversion_distribution: ConversionDistribution,
    ) -> Self {
        Self {
            max_conversion_value: NonZeroU32::try_from(max_conversion_value).unwrap(),
            max_breakdown_key: NonZeroU32::try_from(max_breakdown_key).unwrap(),
            conversion_distribution,
        }
    }
}

pub struct EventGenerator<R: Rng> {
    config: Config,
    rng: R,
    in_flight: Vec<TestHybridRecord>,
}

impl<R: Rng> EventGenerator<R> {
    #[allow(dead_code)]
    pub fn with_default_config(rng: R) -> Self {
        Self::with_config(rng, Config::default())
    }

    /// # Panics
    /// If the configuration is not valid.
    #[allow(dead_code)]
    pub fn with_config(rng: R, config: Config) -> Self {
        let max_capacity = 2;
        Self {
            config,
            rng,
            in_flight: Vec::with_capacity(max_capacity),
        }
    }

    fn gen_batch(&mut self) {
        match self.config.conversion_distribution {
            ConversionDistribution::OnlyImpressions => {
                self.gen_batch_with_params(0.0, 1.0);
            }
            ConversionDistribution::OnlyConversions => {
                self.gen_batch_with_params(1.0, 0.0);
            }
            ConversionDistribution::Default => {
                self.gen_batch_with_params(0.1, 0.7);
            }
        }
    }

    fn gen_batch_with_params(&mut self, unmatched_conversions: f32, unmatched_impressions: f32) {
        assert!(unmatched_conversions + unmatched_impressions <= 1.0);
        let match_key = self.rng.r#gen::<u64>();
        let rand = self.rng.gen_range(0.0..1.0);
        if rand < unmatched_conversions {
            let conv = self.gen_conversion(match_key);
            self.in_flight.push(conv);
        } else if rand < unmatched_conversions + unmatched_impressions {
            let imp = self.gen_impression(match_key);
            self.in_flight.push(imp);
        } else {
            let imp = self.gen_impression(match_key);
            let conv = self.gen_conversion(match_key);
            self.in_flight.push(imp);
            self.in_flight.push(conv);
        }
    }

    fn gen_conversion(&mut self, match_key: u64) -> TestHybridRecord {
        TestHybridRecord::TestConversion {
            match_key,
            value: self
                .rng
                .gen_range(1..self.config.max_conversion_value.get()),
            key_id: 0,
            conversion_site_domain: "meta.com".to_string(),
            timestamp: self.rng.gen_range(0..1000),
            epsilon: 0.0,
            sensitivity: 0.0,
        }
    }

    fn gen_impression(&mut self, match_key: u64) -> TestHybridRecord {
        TestHybridRecord::TestImpression {
            match_key,
            breakdown_key: self.rng.gen_range(0..self.config.max_breakdown_key.get()),
            key_id: 0,
        }
    }
}

impl<R: Rng> Iterator for EventGenerator<R> {
    type Item = TestHybridRecord;

    fn next(&mut self) -> Option<Self::Item> {
        if self.in_flight.is_empty() {
            self.gen_batch();
        }
        Some(self.in_flight.pop().unwrap())
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        iter::zip,
    };

    use rand::thread_rng;

    use super::*;

    #[test]
    fn iter() {
        let event_gen = EventGenerator::with_default_config(thread_rng());
        assert_eq!(10, event_gen.take(10).collect::<Vec<_>>().len());

        let event_gen = EventGenerator::with_default_config(thread_rng());
        assert_eq!(1000, event_gen.take(1000).collect::<Vec<_>>().len());
    }

    #[test]
    fn default_config() {
        // Since there is randomness, the actual number will be a bit different
        // from the expected value.
        // The "tolerance" is used to compute the allowable range of values.
        // It is multiplied by the expected value. So a tolerance of 0.05 means
        // we will accept a value within 5% of the expected value
        const UNMATCHED_CONVERSIONS: f64 = 0.1;
        const UNMATCHED_IMPRESSIONS: f64 = 0.7;
        const PROB_SINGLE: f64 = UNMATCHED_CONVERSIONS + UNMATCHED_IMPRESSIONS;
        const PROB_DOUBLE: f64 = 1.0 - (UNMATCHED_CONVERSIONS + UNMATCHED_IMPRESSIONS);
        const TEST_COUNT: i32 = 1_000_000;
        const EXPECTED_MATCH_KEYS: f64 = TEST_COUNT as f64 / (PROB_SINGLE + 2.0 * PROB_DOUBLE);
        const EXPECTED_SINGLE: f64 = EXPECTED_MATCH_KEYS * PROB_SINGLE;
        const EXPECTED_DOUBLE: f64 = EXPECTED_MATCH_KEYS * PROB_DOUBLE;

        const EXPECTED_HISTOGRAM_WITH_TOLERANCE: [(f64, f64); 3] =
            [(0.0, 0.0), (EXPECTED_SINGLE, 0.01), (EXPECTED_DOUBLE, 0.02)];

        let event_gen = EventGenerator::with_default_config(thread_rng());
        let mut match_key_to_event_count = HashMap::new();
        for event in event_gen.take(TEST_COUNT.try_into().unwrap()) {
            match event {
                TestHybridRecord::TestImpression { match_key, .. } => {
                    match_key_to_event_count
                        .entry(match_key)
                        .and_modify(|count| *count += 1)
                        .or_insert(1);
                }
                TestHybridRecord::TestConversion { match_key, .. } => {
                    match_key_to_event_count
                        .entry(match_key)
                        .and_modify(|count| *count += 1)
                        .or_insert(1);
                }
            }
        }
        let histogram_size = 3;
        let mut histogram: Vec<i32> = vec![0; histogram_size];
        for (_, count) in match_key_to_event_count {
            histogram[count] += 1;
        }

        for (actual, (expected, tolerance)) in
            zip(histogram, EXPECTED_HISTOGRAM_WITH_TOLERANCE.iter())
        {
            // Adding a constant value of 10 is a way of dealing with the high variability small values
            // which will vary a lot more (as a percent). Because 10 is an increasingly large percentage of
            // A smaller and smaller expected value
            let max_tolerance = expected * tolerance + 10.0;
            assert!(
                (expected - f64::from(actual)).abs() <= max_tolerance,
                "{:?} is outside of the expected range: ({:?}..{:?})",
                actual,
                expected - max_tolerance,
                expected + max_tolerance,
            );
        }
    }

    #[test]
    fn only_impressions_config() {
        const NUM_EVENTS: usize = 100;
        const MAX_BREAKDOWN_KEY: u32 = 10;
        let event_gen = EventGenerator::with_config(
            thread_rng(),
            Config::new(
                10,
                MAX_BREAKDOWN_KEY,
                ConversionDistribution::OnlyImpressions,
            ),
        );
        let mut match_keys = HashSet::new();
        for event in event_gen.take(NUM_EVENTS) {
            match event {
                TestHybridRecord::TestImpression {
                    match_key,
                    breakdown_key,
                    ..
                } => {
                    assert!(breakdown_key <= MAX_BREAKDOWN_KEY);
                    match_keys.insert(match_key);
                }
                TestHybridRecord::TestConversion { .. } => {
                    panic!("No conversions should be generated");
                }
            }
        }
        assert_eq!(match_keys.len(), NUM_EVENTS);
    }

    #[test]
    fn only_conversions_config() {
        const NUM_EVENTS: usize = 100;
        const MAX_VALUE: u32 = 10;
        let event_gen = EventGenerator::with_config(
            thread_rng(),
            Config::new(MAX_VALUE, 10, ConversionDistribution::OnlyConversions),
        );
        let mut match_keys = HashSet::new();
        for event in event_gen.take(NUM_EVENTS) {
            match event {
                TestHybridRecord::TestConversion {
                    match_key, value, ..
                } => {
                    assert!(value <= MAX_VALUE);
                    match_keys.insert(match_key);
                }
                TestHybridRecord::TestImpression { .. } => {
                    panic!("No impressions should be generated");
                }
            }
        }
        assert_eq!(match_keys.len(), NUM_EVENTS);
    }
}
