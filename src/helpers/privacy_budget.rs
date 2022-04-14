#![allow(dead_code)]

use crate::error::Res;
use redis::{transaction, Commands, RedisWrite, ToRedisArgs};
use rust_elgamal::RistrettoPoint;
#[derive(Debug, PartialEq, Eq)]
struct BlindedMatchKey(RistrettoPoint);

impl BlindedMatchKey {
    pub fn new(key: RistrettoPoint) -> Self {
        Self(key)
    }
}

impl ToRedisArgs for BlindedMatchKey {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        // let (c0, c1) = self.0.inner();
        out.write_arg(self.0.compress().as_bytes());
    }
}

/// This module implements privacy budget using a redis cache
struct PrivacyBudget {
    redis_connection: redis::Connection,
    total_privacy_budget: u32,
}

impl PrivacyBudget {
    fn new(redis_host_name: &str, redis_password: &str, is_tls: bool) -> Res<PrivacyBudget> {
        //if Redis server needs secure connection
        let uri_scheme = if is_tls { "rediss" } else { "redis" };

        let redis_conn_url = format!("{}://:{}@{}", uri_scheme, redis_password, redis_host_name);

        let redis_connection = redis::Client::open(redis_conn_url)?.get_connection()?;

        Ok(PrivacyBudget {
            redis_connection,
            total_privacy_budget: 100,
        })
    }

    /// Input : a vector of blinded match keys alongwith budget to be consumed.
    /// This atomically increases the budget of all of the blinded match keys which have
    /// sufficient budget to consume. For those which do not pass, match keys are discarded and not passed to the output.
    pub fn consume_budget_and_return_for_eligible_bmks<'a>(
        &'a mut self,
        blinded_match_keys: impl Iterator<Item = &'a BlindedMatchKey>,
        budget_to_consume: u32,
    ) -> impl Iterator<Item = &'a BlindedMatchKey> {
        blinded_match_keys.filter(move |blinded_match_key| {
            match self.increase_budget_consumed(blinded_match_key, budget_to_consume) {
                Ok(true) => true,
                Ok(false) | Err(_) => false,
            }
        })
    }

    pub fn get_total_privacy_budget(&self) -> u32 {
        self.total_privacy_budget
    }

    /// Budget is increased for each key atomically in Redis
    fn increase_budget_consumed(
        &mut self,
        blinded_match_key: &BlindedMatchKey,
        budget_to_consume: u32,
    ) -> Res<bool> {
        let total_privacy_budget = self.get_total_privacy_budget();

        Ok(transaction(
            &mut self.redis_connection,
            &[blinded_match_key],
            |con, pipe| {
                let val: u32 = con.get(&blinded_match_key).unwrap_or(0);
                if val + budget_to_consume > total_privacy_budget {
                    pipe.set(&blinded_match_key, val)
                        .ignore()
                        .query::<()>(con)?;
                    Ok(Some(false))
                } else {
                    // increment
                    pipe.set(&blinded_match_key, val + budget_to_consume)
                        .ignore()
                        .query::<()>(con)?;
                    Ok(Some(true))
                }
            },
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;
    use rand::thread_rng;
    use std::sync::Mutex;

    lazy_static! {
        static ref PRIVACY_BUDGET: Mutex<PrivacyBudget> =
            Mutex::new(PrivacyBudget::new("127.0.0.1", "", false).unwrap());
    }

    impl Drop for BlindedMatchKey {
        fn drop(&mut self) {
            clear_redis_key(self);
        }
    }

    fn clear_redis_key(blinded_match_key: &BlindedMatchKey) {
        let mut privacy_budget = PRIVACY_BUDGET.lock().unwrap();
        privacy_budget
            .redis_connection
            .del::<&BlindedMatchKey, ()>(blinded_match_key)
            .expect("Failed to delete keys");
    }

    fn create_blinded_match_keys() -> [BlindedMatchKey; 4] {
        let mut rng = thread_rng();

        let c1 = BlindedMatchKey::new(RistrettoPoint::random(&mut rng));
        let c2 = BlindedMatchKey::new(RistrettoPoint::random(&mut rng));
        let c3 = BlindedMatchKey::new(RistrettoPoint::random(&mut rng));
        let c4 = BlindedMatchKey::new(RistrettoPoint::random(&mut rng));

        [c1, c2, c3, c4]
    }

    #[test]
    fn privacy_budget_didnot_exceed() {
        let mut privacy_budget = PRIVACY_BUDGET.lock().unwrap();
        let blinded_match_keys = create_blinded_match_keys();
        let mut eligible_bmk = privacy_budget
            .consume_budget_and_return_for_eligible_bmks(blinded_match_keys.iter(), 20);
        let ok0 = eligible_bmk.next() == Some(&blinded_match_keys[0]);
        let ok1 = eligible_bmk.next() == Some(&blinded_match_keys[1]);
        let ok2 = eligible_bmk.next() == Some(&blinded_match_keys[2]);
        let ok3 = eligible_bmk.next() == Some(&blinded_match_keys[3]);

        drop(eligible_bmk);
        drop(privacy_budget);

        assert!(ok0 && ok1 && ok2 && ok3);
    }

    #[test]
    fn privacy_budget_exceed() {
        let mut privacy_budget = PRIVACY_BUDGET.lock().unwrap();
        let blinded_match_keys = create_blinded_match_keys();
        let mut eligible_bmk = privacy_budget
            .consume_budget_and_return_for_eligible_bmks(blinded_match_keys.iter(), 120);

        let ok = eligible_bmk.next() == None;

        drop(eligible_bmk);
        drop(privacy_budget);
        assert!(ok);
    }

    #[test]
    fn privacy_budget_multiple_runs_exceed() {
        let mut privacy_budget = PRIVACY_BUDGET.lock().unwrap();
        let blinded_match_keys = create_blinded_match_keys();
        let mut eligible_bmk = privacy_budget
            .consume_budget_and_return_for_eligible_bmks(blinded_match_keys.iter(), 20);

        let ok0 = eligible_bmk.next() == Some(&blinded_match_keys[0]);
        let ok1 = eligible_bmk.next() == Some(&blinded_match_keys[1]);
        let ok2 = eligible_bmk.next() == Some(&blinded_match_keys[2]);
        let ok3 = eligible_bmk.next() == Some(&blinded_match_keys[3]);

        drop(eligible_bmk);
        drop(privacy_budget);

        assert!(ok0 && ok1 && ok2 && ok3);

        privacy_budget = PRIVACY_BUDGET.lock().unwrap();
        let mut eligible_bmk = privacy_budget
            .consume_budget_and_return_for_eligible_bmks(blinded_match_keys.iter(), 90);

        let ok = eligible_bmk.next() == None;
        drop(eligible_bmk);
        drop(privacy_budget);
        assert!(ok);
    }

    #[test]
    fn privacy_budget_multiple_runs_mix() {
        let mut privacy_budget = PRIVACY_BUDGET.lock().unwrap();
        let blinded_match_keys = create_blinded_match_keys();

        let mut eligible_bmk = privacy_budget
            .consume_budget_and_return_for_eligible_bmks((blinded_match_keys[..3]).iter(), 80);

        let ok0 = eligible_bmk.next() == Some(&blinded_match_keys[0]);
        let ok1 = eligible_bmk.next() == Some(&blinded_match_keys[1]);
        let ok2 = eligible_bmk.next() == Some(&blinded_match_keys[2]);

        drop(eligible_bmk);
        drop(privacy_budget);

        assert!(ok0 && ok1 && ok2);

        let mut privacy_budget = PRIVACY_BUDGET.lock().unwrap();
        let mut eligible_bmk = privacy_budget
            .consume_budget_and_return_for_eligible_bmks(blinded_match_keys.iter(), 90);

        let ok3 = eligible_bmk.next() == Some(&blinded_match_keys[3]);
        drop(eligible_bmk);
        drop(privacy_budget);

        assert!(ok3);

        let mut privacy_budget = PRIVACY_BUDGET.lock().unwrap();
        let mut eligible_bmk = privacy_budget
            .consume_budget_and_return_for_eligible_bmks(blinded_match_keys.iter(), 20);

        let ok0 = eligible_bmk.next() == Some(&blinded_match_keys[0]);
        let ok1 = eligible_bmk.next() == Some(&blinded_match_keys[1]);
        let ok2 = eligible_bmk.next() == Some(&blinded_match_keys[2]);
        drop(eligible_bmk);
        drop(privacy_budget);

        assert!(ok0 && ok1 && ok2);
    }
}
