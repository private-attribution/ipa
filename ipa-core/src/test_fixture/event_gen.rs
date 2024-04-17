use std::{
    collections::HashSet,
    num::{NonZeroU32, NonZeroU64},
};

use crate::{rand::Rng, test_fixture::ipa::TestRawDataRecord};

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

// 7 days = 604800 seconds fits in 20 bits
pub type Timestamp = u32;
pub type NonZeroTimestamp = NonZeroU32;

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
    pub max_timestamp: NonZeroTimestamp,
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
        max_timestamp: Timestamp,
    ) -> Self {
        Self {
            user_count: NonZeroU64::try_from(user_count).unwrap(),
            max_trigger_value: NonZeroU32::try_from(max_trigger_value).unwrap(),
            max_breakdown_key: NonZeroU32::try_from(max_breakdown_key).unwrap(),
            max_timestamp: NonZeroTimestamp::try_from(max_timestamp).unwrap(),
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

struct UserStats {
    user_id: UserId,
    generated: u32,
    max: u32,
    used_timestamps: HashSet<Timestamp>,
}

impl UserStats {
    fn new(user_id: UserId, max_events: u32) -> Self {
        Self {
            user_id,
            generated: 0,
            max: max_events,
            used_timestamps: HashSet::new(),
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
    used_ids: HashSet<UserId>,
}

impl<R: Rng> EventGenerator<R> {
    pub fn with_default_config(rng: R) -> Self {
        Self::with_config(rng, Config::default())
    }

    /// # Panics
    /// If the configuration is not valid.
    pub fn with_config(rng: R, config: Config) -> Self {
        assert!(config.min_events_per_user <= config.max_events_per_user);
        // Ensure that rejection-sampling of non-duplicate timestamps
        // will complete in a reasonable amount of time.
        assert!(
            2 * config.max_events_per_user.get() <= config.max_timestamp.get(),
            "max_timestamp ({mt}) must be at least twice max_events_per_user ({me}) \
             to support generation of a unique timestamp for each event",
            mt = config.max_timestamp,
            me = config.max_events_per_user,
        );
        Self {
            config,
            rng,
            users: vec![],
            used_ids: HashSet::new(),
        }
    }

    fn gen_event(&mut self, idx: usize) -> TestRawDataRecord {
        let user_id = self.users[idx].user_id;

        // Generate a new random timestamp between [0..`max_timestamp`) and distinct from
        // already-used timestamps. `EventGenerator::with_config` checks that `max_timestamp`
        // exceeds `max_events_per_user` by a margin large enough that this is likely to complete.
        let current_ts = loop {
            let ts = self.rng.gen_range(0..self.config.max_timestamp.get());
            if self.users[idx].used_timestamps.insert(ts) {
                break ts;
            }
        };

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

    fn gen_trigger(&mut self, user_id: UserId, timestamp: Timestamp) -> TestRawDataRecord {
        let trigger_value = self.rng.gen_range(1..=self.config.max_trigger_value.get());

        TestRawDataRecord {
            user_id: user_id.into(),
            timestamp: timestamp.into(),
            is_trigger_report: true,
            breakdown_key: 0,
            trigger_value,
        }
    }

    fn gen_source(&mut self, user_id: UserId, timestamp: Timestamp) -> TestRawDataRecord {
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
        if self.used_ids.len() == self.config.user_count() {
            return None;
        }

        loop {
            let user_id = UserId::from(
                self.rng
                    .gen_range(UserId::FIRST.into()..=self.config.user_count.get()),
            );
            if self.used_ids.contains(&user_id) {
                continue;
            }
            self.used_ids.insert(user_id);

            break Some(UserStats::new(
                user_id,
                self.rng.gen_range(
                    self.config.min_events_per_user.get()..=self.config.max_events_per_user.get(),
                ),
            ));
        }
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
        let event = self.gen_event(idx);

        if self.users[idx].add_one() {
            self.users.swap_remove(idx);
        }

        Some(event)
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

    #[test]
    #[should_panic(expected = "must be at least twice max_events_per_user")]
    fn invalid_max_timestamp() {
        let _ = EventGenerator::with_config(
            thread_rng(),
            Config {
                max_events_per_user: NonZeroU32::new(10).unwrap(),
                max_timestamp: NonZeroTimestamp::new(10).unwrap(),
                ..Config::default()
            },
        );
    }

    #[test]
    fn min_max_trigger_value() {
        let mut gen = EventGenerator::with_config(
            thread_rng(),
            Config {
                max_trigger_value: NonZeroU32::new(1).unwrap(),
                report_filter: ReportFilter::TriggerOnly,
                conversion_probability: Some(1.0),
                ..Config::default()
            },
        );

        assert!(gen.next().is_some());
    }

    mod proptests {
        use std::collections::HashMap;

        use proptest::{
            prelude::{Just, Strategy},
            prop_compose, prop_oneof, proptest,
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

                assert!(
                    event.timestamp < u64::from(self.max_timestamp.get()),
                    "Timestamp should not exceed configured maximum",
                );
            }
        }

        prop_compose! {
            fn arb_config()
                (max_events_per_user in 1..u32::MAX / 2)
                (
                    max_trigger_value in 1..u32::MAX,
                    max_breakdown_key in 1..u32::MAX,
                    min_events_per_user in 1..=max_events_per_user,
                    max_events_per_user in Just(max_events_per_user),
                    max_timestamp in max_events_per_user*2..=u32::MAX,
                    report_filter in report_filter_strategy(),
                )
             -> Config {
                Config {
                    user_count: NonZeroU64::new(10_000).unwrap(),
                    max_trigger_value: NonZeroU32::new(max_trigger_value).unwrap(),
                    max_breakdown_key: NonZeroU32::new(max_breakdown_key).unwrap(),
                    max_timestamp: NonZeroTimestamp::new(max_timestamp).unwrap(),
                    min_events_per_user: NonZeroU32::new(min_events_per_user).unwrap(),
                    max_events_per_user: NonZeroU32::new(max_events_per_user).unwrap(),
                    report_filter,
                    conversion_probability: match report_filter {
                        ReportFilter::TriggerOnly => Some(0.02),
                        _ => None,
                    },
                }
            }
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

                // Basic correctness checks.
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
