use rand::distributions::WeightedIndex;
use rand::{CryptoRng, Rng, RngCore};
use rand_distr::{num_traits::ToPrimitive, Distribution, Normal};
use std::ops::Range;
use std::time::Duration;

const DEVICES_PER_USER_DISTR_WEIGHT: [(u8, f64); 10] = [
    (0, 0.0),
    (1, 0.60),
    (2, 0.31),
    (3, 0.085),
    (4, 0.002),
    (5, 0.001),
    (6, 0.001),
    (7, 0.001),
    (8, 0.0),
    (9, 0.0),
];
const CVR_PER_ADACCOUNT_DISTR_WEIGHT: [(Range<f64>, f64); 10] = [
    (0.000..0.000, 0.0),
    (0.001..0.002, 0.100),
    (0.002..0.004, 0.200),
    (0.004..0.007, 0.300),
    (0.007..0.010, 0.200),
    (0.010..0.015, 0.080),
    (0.015..0.020, 0.020),
    (0.020..0.030, 0.007),
    (0.030..0.050, 0.002),
    (0.050..0.100, 0.001),
];
const AD_IMPRESSION_PER_AD_DISTR_WEIGHT: [(Range<u32>, f64); 6] = [
    (1..100, 0.055),
    (100..1000, 0.250),
    (1000..2000, 0.200),
    (2000..5000, 0.190),
    (5000..10000, 0.175),
    (10000..50000, 0.130),
];
const AD_IMPRESSION_PER_USER_DISTR_WEIGHT: [(u8, f64); 10] = [
    (0, 0.0),
    (1, 0.845),
    (2, 0.105),
    (3, 0.026),
    (4, 0.010),
    (5, 0.005),
    (6, 0.004),
    (7, 0.003),
    (8, 0.002),
    (9, 0.001),
];
const AD_CONVERSION_DISTR_WEIGHT: [(u8, f64); 10] = [
    (0, 0.0),
    (1, 0.800),
    (2, 0.090),
    (3, 0.030),
    (4, 0.020),
    (5, 0.010),
    (6, 0.015),
    (7, 0.013),
    (8, 0.011),
    (9, 0.011),
];
const CONVERSIONS_DURATION_DISTR: [(Range<u32>, f64); 10] = [
    // Duration from impression to conversion in days
    (0..1, 0.320),
    (1..2, 0.080),
    (2..4, 0.100),
    (4..7, 0.110),
    (7..10, 0.075),
    (10..12, 0.035),
    (12..14, 0.040),
    (14..17, 0.050),
    (17..20, 0.045),
    (20..28, 0.145),
];

pub struct Sample {
    // Event Count
    reach_per_ad_distr: WeightedIndex<f64>,
    cvr_per_adaccount_distr: WeightedIndex<f64>,
    ad_impression_per_user_distr: WeightedIndex<f64>,
    ad_conversion_per_user_distr: WeightedIndex<f64>,

    // Match key
    devices_per_user_distr: WeightedIndex<f64>,

    // Time
    conversions_duration_distr: WeightedIndex<f64>,
    frequency_cap_distr: Normal<f64>,

    // Trigger value
    trigger_value_distr: Normal<f64>,
}

impl Sample {
    // <# of events> = X = DEFAULT_EVENT_GEN_COUNT * scale
    // # of events per day = impressions/day + conversions/day
    // impressions per day = devices * impression/device/day
    pub fn new() -> Self {
        Self {
            reach_per_ad_distr: WeightedIndex::new(
                AD_IMPRESSION_PER_AD_DISTR_WEIGHT.iter().map(|i| i.1),
            )
            .unwrap(),
            cvr_per_adaccount_distr: WeightedIndex::new(
                CVR_PER_ADACCOUNT_DISTR_WEIGHT.iter().map(|i| i.1),
            )
            .unwrap(),
            ad_impression_per_user_distr: WeightedIndex::new(
                AD_IMPRESSION_PER_USER_DISTR_WEIGHT.iter().map(|i| i.1),
            )
            .unwrap(),
            ad_conversion_per_user_distr: WeightedIndex::new(
                AD_CONVERSION_DISTR_WEIGHT.iter().map(|i| i.1),
            )
            .unwrap(),

            devices_per_user_distr: WeightedIndex::new(
                DEVICES_PER_USER_DISTR_WEIGHT.iter().map(|i| i.1),
            )
            .unwrap(),

            conversions_duration_distr: WeightedIndex::new(
                CONVERSIONS_DURATION_DISTR.iter().map(|i| i.1),
            )
            .unwrap(),
            // FB Feed = >2hrs, IG Feed = >3hrs, IG Stories = >6hrs
            frequency_cap_distr: Normal::new(6.0, 0.5).unwrap(),

            // TODO: Need data
            trigger_value_distr: Normal::new(1000.0, 100.0).unwrap(),
        }
    }

    pub fn reach_per_ad<R: RngCore + CryptoRng>(&self, rng: &mut R) -> u32 {
        // TODO: Using impressions distribution here because 93% of users see only have one impression per ad
        let r = AD_IMPRESSION_PER_AD_DISTR_WEIGHT[self.reach_per_ad_distr.sample(rng)]
            .0
            .clone();
        rng.gen_range(r)
    }

    pub fn devices_per_user<R: RngCore + CryptoRng>(&self, rng: &mut R) -> u8 {
        DEVICES_PER_USER_DISTR_WEIGHT[self.devices_per_user_distr.sample(rng)].0
    }

    pub fn cvr_per_ad_account<R: RngCore + CryptoRng>(&self, rng: &mut R) -> f64 {
        let r = CVR_PER_ADACCOUNT_DISTR_WEIGHT[self.cvr_per_adaccount_distr.sample(rng)]
            .0
            .clone();
        rng.gen_range(r)
    }

    pub fn impression_per_user<R: RngCore + CryptoRng>(&self, rng: &mut R) -> u8 {
        AD_IMPRESSION_PER_USER_DISTR_WEIGHT[self.ad_impression_per_user_distr.sample(rng)].0
    }

    pub fn conversion_per_user<R: RngCore + CryptoRng>(&self, rng: &mut R) -> u8 {
        AD_CONVERSION_DISTR_WEIGHT[self.ad_conversion_per_user_distr.sample(rng)].0
    }

    pub fn conversion_value_per_ad<R: RngCore + CryptoRng>(&self, rng: &mut R) -> u32 {
        self.trigger_value_distr.sample(rng).to_u32().unwrap()
    }

    pub fn impressions_time_diff<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Duration {
        let diff = self.frequency_cap_distr.sample(rng).min(2.0);
        Duration::new((diff * 60.0 * 60.0).floor().to_u64().unwrap(), 0)
    }

    pub fn conversions_time_diff<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Duration {
        let days = CONVERSIONS_DURATION_DISTR[self.conversions_duration_distr.sample(rng)]
            .0
            .clone();
        let diff = rng.gen_range(days);

        // Since [diff] is a range of days, randomly choose hours and seconds for the given range.
        // E.g. return [1..3) days + y hours + z seconds
        Duration::new(diff.to_u64().unwrap() * 24 * 60 * 60, 0)
            + Duration::new(rng.gen_range(0..23) * 60 * 60, 0)
            + Duration::new(rng.gen_range(0..59) * 60, 0)
            + Duration::new(rng.gen_range(0..59), 0)
    }
}
