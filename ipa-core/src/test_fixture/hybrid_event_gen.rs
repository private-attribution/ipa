use std::num::{NonZeroU32, NonZeroU64};

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
    #[cfg_attr(feature = "clap", arg(long, default_value = "1000000000000"))]
    pub num_events: NonZeroU64,
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
        Self::new(1_000, 5, 20, 10)
    }
}

impl Config {
    /// Creates a new instance of [`Self`]
    ///
    /// ## Panics
    /// If any argument is 0.
    #[must_use]
    pub fn new(
        num_events: u64,
        max_conversion_value: u32,
        max_breakdown_key: u32,
        max_convs_per_imp: u32,
    ) -> Self {
        Self {
            num_events: NonZeroU64::try_from(num_events).unwrap(),
            max_conversion_value: NonZeroU32::try_from(max_conversion_value).unwrap(),
            max_breakdown_key: NonZeroU32::try_from(max_breakdown_key).unwrap(),
            max_convs_per_imp: NonZeroU32::try_from(max_convs_per_imp).unwrap(),
            conversion_distribution: ConversionDistribution::Default,
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
    use std::collections::HashMap;

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
    fn subsequent_convs() {
        let gen = EventGenerator::with_default_config(thread_rng());
        let max_convs_per_imp = gen.config.max_convs_per_imp.get();
        let mut match_key_to_event_count = HashMap::new();
        for event in gen.take(10000) {
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

        assert!(
            (6470 - histogram[1]).abs() < 200,
            "expected {:?} unmatched events, got {:?}",
            647,
            histogram[1]
        );

        assert!(
            (1370 - histogram[2]).abs() < 100,
            "expected {:?} unmatched events, got {:?}",
            137,
            histogram[2]
        );

        assert!(
            (200 - histogram[3]).abs() < 50,
            "expected {:?} unmatched events, got {:?}",
            20,
            histogram[3]
        );

        assert!(
            (30 - histogram[4]).abs() < 40,
            "expected {:?} unmatched events, got {:?}",
            3,
            histogram[4]
        );

        assert!(
            (0 - histogram[11]).abs() < 10,
            "expected {:?} unmatched events, got {:?}",
            0,
            histogram[11]
        );
    }
}
