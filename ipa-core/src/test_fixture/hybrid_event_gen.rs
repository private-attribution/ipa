use std::{iter::zip, num::NonZeroU32};

use rand::Rng;

use super::hybrid::TestHybridRecord;

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum ConversionDistribution {
    Default,
    LotsOfConversionsPerImpression,
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
    #[cfg_attr(feature = "clap", arg(long, default_value = "10"))]
    pub max_convs_per_imp: NonZeroU32,
    /// Indicates the distribution of impression to conversion reports.
    #[cfg_attr(feature = "clap", arg(value_enum, long, default_value_t = ConversionDistribution::Default))]
    pub conversion_distribution: ConversionDistribution,
}

impl Default for Config {
    fn default() -> Self {
        Self::new(5, 20, 10, ConversionDistribution::Default)
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
        max_convs_per_imp: u32,
        conversion_distribution: ConversionDistribution,
    ) -> Self {
        Self {
            max_conversion_value: NonZeroU32::try_from(max_conversion_value).unwrap(),
            max_breakdown_key: NonZeroU32::try_from(max_breakdown_key).unwrap(),
            max_convs_per_imp: NonZeroU32::try_from(max_convs_per_imp).unwrap(),
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
        let max_capacity = usize::try_from(config.max_convs_per_imp.get() + 1).unwrap();
        Self {
            config,
            rng,
            in_flight: Vec::with_capacity(max_capacity),
        }
    }

    fn gen_batch(&mut self) {
        match self.config.conversion_distribution {
            ConversionDistribution::OnlyImpressions => {
                self.gen_batch_with_params(0.0, 1.0, 0.0);
            }
            ConversionDistribution::OnlyConversions => {
                self.gen_batch_with_params(1.0, 0.0, 0.0);
            }
            ConversionDistribution::Default => {
                self.gen_batch_with_params(0.1, 0.7, 0.15);
            }
            ConversionDistribution::LotsOfConversionsPerImpression => {
                self.gen_batch_with_params(0.3, 0.4, 0.8);
            }
        }
    }

    fn gen_batch_with_params(
        &mut self,
        unmatched_conversions: f32,
        unmatched_impressions: f32,
        subsequent_conversion_prob: f32,
    ) {
        assert!(unmatched_conversions + unmatched_impressions <= 1.0);
        let match_key = self.rng.gen::<u64>();
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
            let mut conv_count = 1;
            // long-tailed distribution of # of conversions per impression
            // will not exceed the configured maximum number of conversions per impression
            while conv_count < self.config.max_convs_per_imp.get()
                && self.rng.gen_range(0.0..1.0) < subsequent_conversion_prob
            {
                let conv = self.gen_conversion(match_key);
                self.in_flight.push(conv);
                conv_count += 1;
            }
        }
    }

    fn gen_conversion(&mut self, match_key: u64) -> TestHybridRecord {
        TestHybridRecord::TestConversion {
            match_key,
            value: self
                .rng
                .gen_range(1..self.config.max_conversion_value.get()),
        }
    }

    fn gen_impression(&mut self, match_key: u64) -> TestHybridRecord {
        TestHybridRecord::TestImpression {
            match_key,
            breakdown_key: self.rng.gen_range(0..self.config.max_breakdown_key.get()),
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
    use std::collections::{HashMap, HashSet};

    use rand::thread_rng;

    use super::*;

    #[test]
    fn iter() {
        let gen = EventGenerator::with_default_config(thread_rng());
        assert_eq!(10, gen.take(10).collect::<Vec<_>>().len());

        let gen = EventGenerator::with_default_config(thread_rng());
        assert_eq!(1000, gen.take(1000).collect::<Vec<_>>().len());
    }

    #[test]
    fn default_config() {
        // Since there is randomness, the actual number will be a bit different
        // from the expected value.
        // The "tolerance" is used to compute the allowable range of values.
        // It is multiplied by the expected value. So a tolerance of 0.05 means
        // we will accept a value within 5% of the expected value
        const EXPECTED_HISTOGRAM_WITH_TOLERANCE: [(i32, f64); 12] = [
            (0, 0.0), 
            (647634, 0.01), 
            (137626, 0.01), 
            (20652, 0.02),
            (3085, 0.05),
            (463, 0.12),
            (70, 0.5),
            (10, 1.0),
            (2, 1.0),
            (0, 1.0),
            (0, 1.0),
            (0, 1.0),
        ];
        const TEST_COUNT: usize = 1_000_000;
        let gen = EventGenerator::with_default_config(thread_rng());
        let max_convs_per_imp = gen.config.max_convs_per_imp.get();
        let mut match_key_to_event_count = HashMap::new();
        for event in gen.take(TEST_COUNT) {
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
        let histogram_size = usize::try_from(max_convs_per_imp + 2).unwrap();
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
            let max_tolerance = (*expected as f64) * tolerance + 10.0;
            assert!(
                (expected - actual).abs() as f64 <= max_tolerance,
                "{:?} is outside of the expected range: ({:?}..{:?})",
                actual,
                (*expected as f64) - max_tolerance,
                (*expected as f64) + max_tolerance,
            );
        }
    }

    #[test]
    fn lots_of_repeat_conversions() {
        const EXPECTED_HISTOGRAM: [i32; 12] = [
            0, 299296, 25640, 20542, 16421, 13133, 10503, 8417, 6730, 5391, 4289, 17206,
        ];
        const TEST_COUNT: usize = 1_000_000;
        const MAX_CONVS_PER_IMP: u32 = 10;
        const MAX_BREAKDOWN_KEY: u32 = 20;
        const MAX_VALUE: u32 = 3;
        let gen = EventGenerator::with_config(
            thread_rng(),
            Config::new(
                MAX_VALUE,
                MAX_BREAKDOWN_KEY,
                MAX_CONVS_PER_IMP,
                ConversionDistribution::LotsOfConversionsPerImpression,
            ),
        );
        let max_convs_per_imp = gen.config.max_convs_per_imp.get();
        let mut match_key_to_event_count = HashMap::new();
        for event in gen.take(TEST_COUNT) {
            match event {
                TestHybridRecord::TestImpression {
                    match_key,
                    breakdown_key,
                } => {
                    assert!(breakdown_key <= MAX_BREAKDOWN_KEY);
                    match_key_to_event_count
                        .entry(match_key)
                        .and_modify(|count| *count += 1)
                        .or_insert(1);
                }
                TestHybridRecord::TestConversion { match_key, value } => {
                    assert!(value <= MAX_VALUE);
                    match_key_to_event_count
                        .entry(match_key)
                        .and_modify(|count| *count += 1)
                        .or_insert(1);
                }
            }
        }
        let histogram_size = usize::try_from(max_convs_per_imp + 2).unwrap();
        let mut histogram: Vec<i32> = vec![0; histogram_size];
        for (_, count) in match_key_to_event_count {
            histogram[count] += 1;
        }

        for (expected, actual) in zip(EXPECTED_HISTOGRAM.iter(), histogram) {
            let max_tolerance = (*expected as f64) * 0.05 + 10.0;
            assert!(
                (expected - actual).abs() as f64 <= max_tolerance,
                "{:?} is outside of the expected range: ({:?}..{:?})",
                actual,
                (*expected as f64) - max_tolerance,
                (*expected as f64) + max_tolerance,
            );
        }
    }

    #[test]
    fn only_impressions_config() {
        const NUM_EVENTS: usize = 100;
        const MAX_CONVS_PER_IMP: u32 = 1;
        const MAX_BREAKDOWN_KEY: u32 = 10;
        let gen = EventGenerator::with_config(
            thread_rng(),
            Config::new(
                10,
                MAX_BREAKDOWN_KEY,
                MAX_CONVS_PER_IMP,
                ConversionDistribution::OnlyImpressions,
            ),
        );
        let mut match_keys = HashSet::new();
        for event in gen.take(NUM_EVENTS) {
            match event {
                TestHybridRecord::TestImpression {
                    match_key,
                    breakdown_key,
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
        const MAX_CONVS_PER_IMP: u32 = 1;
        const MAX_VALUE: u32 = 10;
        let gen = EventGenerator::with_config(
            thread_rng(),
            Config::new(
                MAX_VALUE,
                10,
                MAX_CONVS_PER_IMP,
                ConversionDistribution::OnlyConversions,
            ),
        );
        let mut match_keys = HashSet::new();
        for event in gen.take(NUM_EVENTS) {
            match event {
                TestHybridRecord::TestConversion { match_key, value } => {
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
