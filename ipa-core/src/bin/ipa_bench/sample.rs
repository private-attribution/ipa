use std::time::Duration;

use rand::{
    CryptoRng, Rng, RngCore,
    distributions::{Distribution, WeightedIndex},
};

use crate::config::Config;

pub struct Sample<'a> {
    config: &'a Config,

    // Event Count
    reach_per_ad_distr: WeightedIndex<f64>,
    cvr_per_adaccount_distr: WeightedIndex<f64>,
    ad_impression_per_user_distr: WeightedIndex<f64>,
    ad_conversion_per_user_distr: WeightedIndex<f64>,

    // Time
    conversions_duration_distr: WeightedIndex<f64>,
    frequency_cap_distr: WeightedIndex<f64>,

    // Trigger value
    trigger_value_distr: WeightedIndex<f64>,
}

impl<'a> Sample<'a> {
    // <# of events> = X = DEFAULT_EVENT_GEN_COUNT * scale
    // # of events per day = impressions/day + conversions/day
    // impressions per day = devices * impression/device/day
    pub fn new(config: &'a Config) -> Self {
        Self {
            config,

            reach_per_ad_distr: WeightedIndex::new(config.reach_per_ad.iter().map(|i| i.weight))
                .unwrap(),
            cvr_per_adaccount_distr: WeightedIndex::new(config.cvr_per_ad.iter().map(|i| i.weight))
                .unwrap(),
            ad_impression_per_user_distr: WeightedIndex::new(
                config.impression_per_user.iter().map(|i| i.weight),
            )
            .unwrap(),
            ad_conversion_per_user_distr: WeightedIndex::new(
                config.conversion_per_user.iter().map(|i| i.weight),
            )
            .unwrap(),

            conversions_duration_distr: WeightedIndex::new(
                config
                    .impression_conversion_duration
                    .iter()
                    .map(|i| i.weight),
            )
            .unwrap(),

            frequency_cap_distr: WeightedIndex::new(
                config
                    .impression_impression_duration
                    .iter()
                    .map(|i| i.weight),
            )
            .unwrap(),

            // TODO: Need data
            trigger_value_distr: WeightedIndex::new(
                config.conversion_value_per_user.iter().map(|i| i.weight),
            )
            .unwrap(),
        }
    }

    pub fn reach_per_ad<R: RngCore + CryptoRng>(&self, rng: &mut R) -> u32 {
        let r = self.config.reach_per_ad[self.reach_per_ad_distr.sample(rng)]
            .index
            .clone();
        rng.gen_range(r)
    }

    pub fn cvr_per_ad_account<R: RngCore + CryptoRng>(&self, rng: &mut R) -> f64 {
        let r = self.config.cvr_per_ad[self.cvr_per_adaccount_distr.sample(rng)]
            .index
            .clone();
        rng.gen_range(r)
    }

    pub fn impression_per_user<R: RngCore + CryptoRng>(&self, rng: &mut R) -> u8 {
        self.config.impression_per_user[self.ad_impression_per_user_distr.sample(rng)].index
    }

    pub fn conversion_per_user<R: RngCore + CryptoRng>(&self, rng: &mut R) -> u8 {
        self.config.conversion_per_user[self.ad_conversion_per_user_distr.sample(rng)].index
    }

    pub fn conversion_value_per_ad<R: RngCore + CryptoRng>(&self, rng: &mut R) -> u32 {
        let r = self.config.conversion_value_per_user[self.trigger_value_distr.sample(rng)]
            .index
            .clone();
        rng.gen_range(r)
    }

    pub fn impressions_time_diff<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Duration {
        let r = self.config.impression_impression_duration[self.frequency_cap_distr.sample(rng)]
            .index
            .clone();
        let diff = (rng.gen_range(r) * 60.0 * 60.0).floor();
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Duration::from_secs(diff as u64)
    }

    pub fn conversions_time_diff<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Duration {
        let days = self.config.impression_conversion_duration
            [self.conversions_duration_distr.sample(rng)]
        .index
        .clone();
        let diff = rng.gen_range(days);

        // Since [diff] is a range of days, randomly choose hours and seconds for the given range.
        // E.g. return [1..3) days + y hours + z seconds
        Duration::new(u64::from(diff) * 24 * 60 * 60, 0)
            + Duration::new(rng.gen_range(0..23) * 60 * 60, 0)
            + Duration::new(rng.gen_range(0..59) * 60, 0)
            + Duration::new(rng.gen_range(0..59), 0)
    }
}
