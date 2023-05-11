use std::collections::HashMap;
use crate::rand::Rng;
use crate::test_fixture::ipa::TestRawDataRecord;

type UserId = u32;
const MAX_USER_ID: UserId = 1_000_000_000;

struct Config {
    max_breakdown_key: u32,
    max_users: u32,
    max_events_per_user: u32
}

struct PerUserStats {
    generated: u64
}

struct Stats {
    total_generated: u64,
    per_user: HashMap<UserId, PerUserStats>
}

/// Generates a practically infinite number of random events with guarantee that every next event
/// occurs at the same time or after the previous event.
pub struct EventGenerator<R: Rng> {
    config: Config,
    stats: Stats,
    rng: R
}

impl <R: Rng> EventGenerator<R> {
    pub fn sample_user<R: Rng>(&mut self) -> UserId {
        let valid = |user_id| {
            self.stat
        }


        let next = self.rng.next_u32();
        if
    }
}


impl Iterator for EventGenerator {
    type Item = TestRawDataRecord;

    fn next(&mut self) -> Option<Self::Item> {
        let user =
    }
}