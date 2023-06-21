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

#[derive(Debug)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct Config {
    #[cfg_attr(feature = "clap", arg(long, default_value = "1000000000000"))]
    pub max_user_id: NonZeroU64,
    #[cfg_attr(feature = "clap", arg(long, default_value = "5"))]
    pub max_trigger_value: NonZeroU32,
    #[cfg_attr(feature = "clap", arg(long, default_value = "20"))]
    pub max_breakdown_key: NonZeroU32,
    #[cfg_attr(feature = "clap", arg(long, default_value = "10"))]
    pub max_events_per_user: NonZeroU32,
}

impl Default for Config {
    fn default() -> Self {
        Self::new(1_000_000_000_000, 5, 20, 50)
    }
}

impl Config {
    /// Creates a new instance of [`Self`]
    ///
    /// ## Panics
    /// If any argument is 0.
    #[must_use]
    pub fn new(
        max_user_id: u64,
        max_trigger_value: u32,
        max_breakdown_key: u32,
        max_events_per_user: u32,
    ) -> Self {
        Self {
            max_user_id: NonZeroU64::try_from(max_user_id).unwrap(),
            max_trigger_value: NonZeroU32::try_from(max_trigger_value).unwrap(),
            max_breakdown_key: NonZeroU32::try_from(max_breakdown_key).unwrap(),
            max_events_per_user: NonZeroU32::try_from(max_events_per_user).unwrap(),
        }
    }

    fn max_user_id(&self) -> usize {
        usize::try_from(self.max_user_id.get()).unwrap()
    }
}

use crate::{rand::Rng, test_fixture::ipa::TestRawDataRecord};
use std::{
    collections::HashSet,
    num::{NonZeroU32, NonZeroU64},
};

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
    // even bit vector takes too long to initialize for MAX_USER_ID. Need a sparse structure
    // here
    used: HashSet<UserId>,
    current_ts: u64,
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
            current_ts: 0,
        }
    }

    fn gen_event(&mut self, user_id: UserId) -> TestRawDataRecord {
        if self.rng.gen() {
            // The next event would have timestamp upto 60 seconds after the previous
            // event generated. On an average, we should be able to start seeing spacing
            // of 7 days in query size of 100k or greater.
            self.current_ts += self.rng.gen_range(1..=60);
        }

        if self.rng.gen() {
            self.gen_trigger(user_id)
        } else {
            self.gen_source(user_id)
        }
    }

    fn gen_trigger(&mut self, user_id: UserId) -> TestRawDataRecord {
        let trigger_value = self.rng.gen_range(1..self.config.max_trigger_value.get());

        TestRawDataRecord {
            user_id: user_id.into(),
            timestamp: self.current_ts,
            is_trigger_report: true,
            breakdown_key: 0,
            trigger_value,
        }
    }

    fn gen_source(&mut self, user_id: UserId) -> TestRawDataRecord {
        let breakdown_key = self.rng.gen_range(0..self.config.max_breakdown_key.get());

        TestRawDataRecord {
            user_id: user_id.into(),
            timestamp: self.current_ts,
            is_trigger_report: false,
            breakdown_key,
            trigger_value: 0,
        }
    }

    fn sample_user(&mut self) -> Option<UserStats> {
        if self.used.len() == self.config.max_user_id() + 1 {
            return None;
        }

        let valid = |user_id| -> bool { !self.used.contains(&user_id) };

        Some(loop {
            let next = UserId::from(self.rng.gen_range(0..=self.config.max_user_id.get()));
            if valid(next) {
                self.used.insert(next);
                break UserStats::new(
                    next,
                    self.rng
                        .gen_range(1..=self.config.max_events_per_user.get()),
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

#[cfg(all(test, not(feature = "shuttle"), feature = "in-memory-infra"))]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn iter() {
        let gen = EventGenerator::with_default_config(thread_rng());
        assert_eq!(10, gen.take(10).collect::<Vec<_>>().len());

        let gen = EventGenerator::with_default_config(thread_rng());
        assert_eq!(59, gen.take(59).collect::<Vec<_>>().len());
    }

    #[test]
    fn exhaust() {
        let mut gen = EventGenerator::with_config(
            thread_rng(),
            Config {
                max_user_id: NonZeroU64::new(1).unwrap(),
                max_events_per_user: NonZeroU32::new(1).unwrap(),
                ..Config::default()
            },
        );

        assert!(gen.next().is_some());
        assert!(gen.next().is_some());
        assert!(gen.next().is_none());
    }

    mod proptests {
        use super::*;
        use proptest::{prelude::Strategy, proptest};
        use rand::rngs::StdRng;
        use rand_core::SeedableRng;
        use std::collections::HashMap;

        fn arb_config() -> impl Strategy<Value = Config> {
            (1..u32::MAX, 1..u32::MAX, 1..u32::MAX).prop_map(
                |(max_trigger_value, max_breakdown_key, max_events_per_user)| Config {
                    max_user_id: NonZeroU64::new(10_000).unwrap(),
                    max_trigger_value: NonZeroU32::new(max_trigger_value).unwrap(),
                    max_breakdown_key: NonZeroU32::new(max_breakdown_key).unwrap(),
                    max_events_per_user: NonZeroU32::new(max_events_per_user).unwrap(),
                },
            )
        }

        fn does_not_exceed_config_maximums(rng_seed: u64, config: &Config, total_events: usize) {
            let max_breakdown = config.max_breakdown_key.get();
            let max_events = config.max_events_per_user.get();

            let gen = EventGenerator::with_default_config(StdRng::seed_from_u64(rng_seed));
            let mut events_per_users = HashMap::<_, u32>::new();
            let mut last_ts = 0;
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

                // basic correctness checks
                assert!(
                    event.timestamp >= last_ts,
                    "Found an event with timestamp preceding the previous event timestamp"
                );
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

                last_ts = event.timestamp;
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
