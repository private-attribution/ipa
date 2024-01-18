#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
struct UserId(u64);

impl From<u64> for UserId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<UserId> for u64 {
    fn from(value: UserId) -> Self {
        value.0
    }
}

impl From<UserId> for usize {
    fn from(value: UserId) -> Self {
        usize::try_from(value.0).unwrap()
    }
}

impl UserId {
    /// 0 is reserved for ephemeral conversions, i.e. conversions that occurred without
    /// an impression
    pub const EPHEMERAL: Self = Self(0);
    pub const FIRST: Self = Self(1);
}

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum ReportFilter {
    All,
    TriggerOnly,
    SourceOnly,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct Config {
    /// Number of unique users per event generator. The generator will generate events
    /// for at most this many users.
    #[cfg_attr(feature = "clap", arg(long, default_value = "1000000000000"))]
    pub user_count: NonZeroU64,
    #[cfg_attr(feature = "clap", arg(long, default_value = "5"))]
    pub max_trigger_value: NonZeroU32,
    #[cfg_attr(feature = "clap", arg(long, default_value = "20"))]
    pub max_breakdown_key: NonZeroU32,
    #[cfg_attr(feature = "clap", arg(long, hide = true, default_value = "604800"))]
    // 7 days < 20 bits
    pub max_timestamp: NonZeroU32,
    #[cfg_attr(feature = "clap", arg(long, default_value = "10"))]
    pub max_events_per_user: NonZeroU32,
    #[cfg_attr(feature = "clap", arg(long, default_value = "1"))]
    pub min_events_per_user: NonZeroU32,
    /// Indicates the types of reports that will appear in the output. Possible values
    /// are: only impressions, only conversions or both.
    #[cfg_attr(feature = "clap", arg(value_enum, long, default_value_t = ReportFilter::All))]
    pub report_filter: ReportFilter,
    #[cfg_attr(feature = "clap", arg(long, required_if_eq("report_filter", "TriggerOnly"), default_value = "0.02", value_parser = validate_probability))]
    pub conversion_probability: Option<f32>,
}

fn validate_probability(value: &str) -> Result<f32, String> {
    let v = value
        .parse::<f32>()
        .map_err(|e| format!("{e} not a float number"))?;
    if (0.0..=1.0).contains(&v) {
        Ok(v)
    } else {
        Err(format!("probability must be between 0.0 and 1.0, got {v}"))
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new(1_000_000_000_000, 5, 20, 1, 50, 604_800)
    }
}

impl Config {
    /// Creates a new instance of [`Self`]
    ///
    /// ## Panics
    /// If any argument is 0.
    #[must_use]
    pub fn new(
        user_count: u64,
        max_trigger_value: u32,
        max_breakdown_key: u32,
        min_events_per_user: u32,
        max_events_per_user: u32,
        max_timestamp: u32,
    ) -> Self {
        assert!(min_events_per_user < max_events_per_user);
        Self {
            user_count: NonZeroU64::try_from(user_count).unwrap(),
            max_trigger_value: NonZeroU32::try_from(max_trigger_value).unwrap(),
            max_breakdown_key: NonZeroU32::try_from(max_breakdown_key).unwrap(),
            max_timestamp: NonZeroU32::try_from(max_timestamp).unwrap(),
            min_events_per_user: NonZeroU32::try_from(min_events_per_user).unwrap(),
            max_events_per_user: NonZeroU32::try_from(max_events_per_user).unwrap(),
            report_filter: ReportFilter::All,
            conversion_probability: None,
        }
    }

    /// Returns the number of unique users per event generator. The generator will generate
    /// events for at most this many users.
    fn user_count(&self) -> usize {
        usize::try_from(self.user_count.get()).unwrap()
    }
}

use std::{
    collections::HashSet,
    num::{NonZeroU32, NonZeroU64},
};

use crate::{rand::Rng, test_fixture::ipa::TestRawDataRecord};

struct UserStats {
    user_id: UserId,
    generated: u32,
    max: u32,
}

impl UserStats {
    fn new(user_id: UserId, max_events: u32) -> Self {
        Self {
            user_id,
            generated: 0,
            max: max_events,
        }
    }

    fn add_one(&mut self) -> bool {
        debug_assert!(self.generated < self.max);

        self.generated += 1;
        self.generated == self.max
    }
}

/// Generates random source and trigger events with guarantee that every next event
/// occurs at the same time or after the previous event.
///
/// Number of events generated depends on the configured number of unique users per set
/// and maximum number of events per user. See [`Config`] for more details
///
/// [`Config`]: Config
pub struct EventGenerator<R: Rng> {
    config: Config,
    rng: R,
    users: Vec<UserStats>,
    // even bit vector takes too long to initialize. Need a sparse structure here
    used: HashSet<UserId>,
}

impl<R: Rng> EventGenerator<R> {
    pub fn with_default_config(rng: R) -> Self {
        Self::with_config(rng, Config::default())
    }

    pub fn with_config(rng: R, config: Config) -> Self {
        Self {
            config,
            rng,
            users: vec![],
            used: HashSet::new(),
        }
    }

    fn gen_event(&mut self, user_id: UserId) -> TestRawDataRecord {
        // Generate a new random timestamp between [0..`max_timestamp`).
        // This means the generated events must be sorted by timestamp before being
        // fed into the IPA protocols.
        let current_ts = self.rng.gen_range(0..self.config.max_timestamp.get());

        match self.config.report_filter {
            ReportFilter::All => {
                if self.rng.gen() {
                    self.gen_trigger(user_id, current_ts)
                } else {
                    self.gen_source(user_id, current_ts)
                }
            }
            ReportFilter::TriggerOnly => {
                // safe to unwrap because clap validation is done before
                let user_id =
                    if self.rng.gen::<f32>() <= self.config.conversion_probability.unwrap() {
                        user_id
                    } else {
                        UserId::EPHEMERAL
                    };
                self.gen_trigger(user_id, current_ts)
            }
            ReportFilter::SourceOnly => self.gen_source(user_id, current_ts),
        }
    }

    fn gen_trigger(&mut self, user_id: UserId, timestamp: u32) -> TestRawDataRecord {
        let trigger_value = self.rng.gen_range(1..self.config.max_trigger_value.get());

        TestRawDataRecord {
            user_id: user_id.into(),
            timestamp: timestamp.into(),
            is_trigger_report: true,
            breakdown_key: 0,
            trigger_value,
        }
    }

    fn gen_source(&mut self, user_id: UserId, timestamp: u32) -> TestRawDataRecord {
        let breakdown_key = self.rng.gen_range(0..self.config.max_breakdown_key.get());

        TestRawDataRecord {
            user_id: user_id.into(),
            timestamp: timestamp.into(),
            is_trigger_report: false,
            breakdown_key,
            trigger_value: 0,
        }
    }

    fn sample_user(&mut self) -> Option<UserStats> {
        if self.used.len() == self.config.user_count() {
            return None;
        }

        let valid = |user_id| -> bool { !self.used.contains(&user_id) };

        Some(loop {
            let next = UserId::from(
                self.rng
                    .gen_range(UserId::FIRST.into()..=self.config.user_count.get()),
            );
            if valid(next) {
                self.used.insert(next);
                break UserStats::new(
                    next,
                    self.rng.gen_range(
                        self.config.min_events_per_user.get()
                            ..=self.config.max_events_per_user.get(),
                    ),
                );
            }
        })
    }
}

impl<R: Rng> Iterator for EventGenerator<R> {
    type Item = TestRawDataRecord;

    fn next(&mut self) -> Option<Self::Item> {
        const USERS_IN_FLIGHT: usize = 10;
        while self.users.len() < USERS_IN_FLIGHT {
            if let Some(next_user) = self.sample_user() {
                self.users.push(next_user);
            } else {
                break;
            }
        }

        if self.users.is_empty() {
            return None;
        }

        let idx = self.rng.gen_range(0..self.users.len());
        let user_id = self.users[idx].user_id;
        if self.users[idx].add_one() {
            self.users.swap_remove(idx);
        }

        Some(self.gen_event(user_id))
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use rand::thread_rng;

    use super::*;

    #[test]
    fn iter() {
        let gen = EventGenerator::with_default_config(thread_rng());
        assert_eq!(10, gen.take(10).collect::<Vec<_>>().len());

        let gen = EventGenerator::with_default_config(thread_rng());
        assert_eq!(59, gen.take(59).collect::<Vec<_>>().len());
    }

    #[test]
    fn exhaust() {
        let gen = EventGenerator::with_config(
            thread_rng(),
            Config {
                user_count: NonZeroU64::new(10).unwrap(),
                min_events_per_user: NonZeroU32::new(10).unwrap(),
                max_events_per_user: NonZeroU32::new(10).unwrap(),
                ..Config::default()
            },
        );

        let mut iter = gen.skip(99);
        assert!(iter.next().is_some());
        assert!(iter.next().is_none());
    }

    mod proptests {
        use std::collections::HashMap;

        use proptest::{
            prelude::{Just, Strategy},
            prop_oneof, proptest,
        };
        use rand::rngs::StdRng;
        use rand_core::SeedableRng;

        use super::*;

        fn report_filter_strategy() -> impl Strategy<Value = ReportFilter> {
            prop_oneof![
                Just(ReportFilter::All),
                Just(ReportFilter::TriggerOnly),
                Just(ReportFilter::SourceOnly),
            ]
        }

        trait Validate {
            fn is_valid(&self, event: &TestRawDataRecord);
        }

        impl Validate for ReportFilter {
            fn is_valid(&self, event: &TestRawDataRecord) {
                match self {
                    ReportFilter::All => {}
                    ReportFilter::TriggerOnly => {
                        assert!(
                            event.is_trigger_report,
                            "Generated a source report when only trigger reports were requested"
                        );
                    }
                    ReportFilter::SourceOnly => {
                        assert!(
                            !event.is_trigger_report,
                            "Generated a trigger report when only source reports were requested"
                        );
                    }
                }
            }
        }

        impl Validate for Config {
            fn is_valid(&self, event: &TestRawDataRecord) {
                self.report_filter.is_valid(event);

                if event.is_trigger_report {
                    assert_eq!(
                        0, event.breakdown_key,
                        "Found a trigger report with breakdown key set"
                    );
                } else {
                    assert_eq!(
                        0, event.trigger_value,
                        "Found source report with trigger value set"
                    );
                }
            }
        }

        fn arb_config() -> impl Strategy<Value = Config> {
            (
                1..u32::MAX,
                1..u32::MAX,
                1..u32::MAX,
                1..u32::MAX,
                report_filter_strategy(),
            )
                .prop_map(
                    |(
                        max_trigger_value,
                        max_breakdown_key,
                        mut min_events_per_user,
                        mut max_events_per_user,
                        report_filter,
                    )| {
                        if min_events_per_user > max_events_per_user {
                            std::mem::swap(&mut min_events_per_user, &mut max_events_per_user);
                        }
                        Config {
                            user_count: NonZeroU64::new(10_000).unwrap(),
                            max_trigger_value: NonZeroU32::new(max_trigger_value).unwrap(),
                            max_breakdown_key: NonZeroU32::new(max_breakdown_key).unwrap(),
                            max_timestamp: NonZeroU32::new(604_800).unwrap(),
                            min_events_per_user: NonZeroU32::new(min_events_per_user).unwrap(),
                            max_events_per_user: NonZeroU32::new(max_events_per_user).unwrap(),
                            report_filter,
                            conversion_probability: match report_filter {
                                ReportFilter::TriggerOnly => Some(0.02),
                                _ => None,
                            },
                        }
                    },
                )
        }

        fn does_not_exceed_config_maximums(rng_seed: u64, config: &Config, total_events: usize) {
            let max_breakdown = config.max_breakdown_key.get();
            let max_events = config.max_events_per_user.get();

            let gen = EventGenerator::with_config(StdRng::seed_from_u64(rng_seed), config.clone());
            let mut events_per_users = HashMap::<_, u32>::new();
            for event in gen.take(total_events) {
                let counter = events_per_users.entry(event.user_id).or_default();
                *counter += 1_u32;
                assert!(
                    *counter < max_events,
                    "Generated more than {max_events} events"
                );
                assert!(
                    event.breakdown_key <= max_breakdown,
                    "Generated breakdown key greater than {max_breakdown}"
                );

                // Basic correctness checks. timestamps are not checked as the order of events
                // is not guaranteed. The caller must sort the events by timestamp before
                // feeding them into IPA.
                config.is_valid(&event);
            }
        }

        proptest! {
            #[test]
            fn iter_test(rng_seed: u64, config in arb_config(), total_events in 1_usize..2000) {
                does_not_exceed_config_maximums(rng_seed, &config, total_events);
            }
        }
    }
}
