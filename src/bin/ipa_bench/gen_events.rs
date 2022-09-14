use super::sample::Sample;
use byteorder::WriteBytesExt;
use log::{debug, info, trace};
use rand::{CryptoRng, Rng, RngCore};
use rand_distr::num_traits::ToPrimitive;
use rand_distr::{Bernoulli, Distribution};
use serde::{Deserialize, Serialize};
use std::io;
use std::time::Duration;

// 0x1E. https://datatracker.ietf.org/doc/html/rfc7464
const RECORD_SEPARATOR: u8 = 30;

const DAYS_IN_EPOCH: u64 = 7;
const SECONDS_IN_A_WEEK: u64 = 604_800;
type MatchKey = u64;
type Epoch = u8;
type Number = u32;

#[derive(Clone, Debug)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct GenericReport {
    // An identifier, set in the user agent, which identifies an individual person. This must never be released (beyond
    /// the match key provider) to any party in unencrypted form. For the purpose of this tool, however, the value is in
    /// clear and not secret shared.
    pub matchkey: MatchKey,

    /// An identifier, specified by the report collector, to denote if a given pair of source and trigger events can be
    /// attributed (beyond having the same match key.) If None, a trigger event will be attributed to all source events.
    pub attribution_constraint_id: Option<Number>,

    /// The epoch which this event is generated. Using an 8-bit value = 256 epochs > 4 years (assuming 1 epoch = 1 week).
    /// This field is in the clear.
    pub epoch: Epoch,

    /// An offset in seconds into a given epoch. The clear is u32 (< 2^20 seconds), then encrypted and secret shared.
    pub timestamp: Number,

    /// 0 (false) if this is a source event. 1 (true) otherwise.
    pub is_trigger_report: bool,

    /// A key, specified by the report collector, which allows for producing aggregates across many groups (or breakdowns.)
    /// This field is only valid if is_trigger_report is [false].
    pub breakdown_key: Number,

    /// The value of the trigger report to be aggregated. This field is only valid if is_trigger_report is [true].
    pub value: Number,
}

impl GenericReport {
    #[must_use]
    pub fn new(
        matchkey: MatchKey,
        attribution_constraint_id: Option<Number>,
        epoch: Epoch,
        timestamp: Number,
        is_trigger_report: bool,
        breakdown_key: Number,
        value: Number,
    ) -> Self {
        Self {
            matchkey,
            attribution_constraint_id,
            epoch,
            timestamp,
            is_trigger_report,
            breakdown_key,
            value,
        }
    }
}

// TODO: Currently, users are mutually exclusive in each ad loop (i.e. User A in ad X will never appear in other ads).
// We need to generate events from same users across ads (but how often should a user appear in different ads?)

pub fn generate_events<R: RngCore + CryptoRng, W: io::Write>(
    sample: &Sample,
    total_count: u32,
    epoch: Epoch,
    rng: &mut R,
    out: &mut W,
) -> (u32, u32) {
    let mut ad_count = 0;
    let mut event_count = 0;
    let mut total_impressions = 0;
    let mut total_conversions = 0;

    // Simulate impressions and conversions from an ad.
    // We define "ad" as a group of impressions and conversions from targeted users who are selected by predefined
    // breakdowns such as age, gender and locations.
    loop {
        ad_count += 1;
        debug!("ad: {}", ad_count);

        // For now, we'll do 1 ad = 1 breakdown key
        let ad_id: u32 = rng.gen();

        // Number of unique people who saw the ad
        let reach = sample.reach_per_ad(rng);
        debug!("reach: {}", reach);

        // CVR for the ad
        let cvr = sample.cvr_per_ad_account(rng);
        debug!("CVR: {}", cvr);

        for _ in 0..reach {
            let impressions = sample.impression_per_user(rng);
            trace!("impressions per user: {}", impressions);

            // Probabilistically decide whether this user has converted or not
            let conversions = if Bernoulli::new(cvr).unwrap().sample(rng) {
                sample.conversion_per_user(rng)
            } else {
                0
            };
            trace!("conversions per user: {}", conversions);

            let events = gen_reports(impressions, conversions, epoch, ad_id, sample, rng);

            total_impressions += impressions.to_u32().unwrap();
            total_conversions += conversions.to_u32().unwrap();

            for e in events {
                out.write_u8(RECORD_SEPARATOR).unwrap();
                out.write_all(serde_json::to_string(&e).unwrap().as_bytes())
                    .unwrap();

                event_count += 1;
                if event_count % 10000 == 0 {
                    info!("{}", event_count);
                }
                if event_count >= total_count {
                    return (total_impressions, total_conversions);
                }
            }
        }
    }
}

fn gen_reports<R: RngCore + CryptoRng>(
    impressions: u8,
    conversions: u8,
    epoch: Epoch,
    breakdown_key: Number,
    sample: &Sample,
    rng: &mut R,
) -> Vec<GenericReport> {
    let mut reports: Vec<GenericReport> = Vec::new();

    let matchkey = gen_matchkey(rng);

    // Randomly choose a datetime of the first impression within [0..DAYS_IN_EPOCH)
    let mut last_impression = Duration::new(rng.gen_range(0..DAYS_IN_EPOCH * 24 * 60 * 60), 0);

    for _ in 0..impressions {
        let t = last_impression + sample.impressions_time_diff(rng);

        // days_in_epoch + sample.impression_time_diff < 4 years < u8::MAX (assuming 1 epoch = 1 week)
        #[allow(clippy::cast_possible_truncation)]
        let new_epoch = epoch + (t.as_secs() / SECONDS_IN_A_WEEK) as u8;

        reports.push(GenericReport::new(
            matchkey,
            None,
            new_epoch,
            u32::try_from(t.as_secs() - u64::from(new_epoch) * SECONDS_IN_A_WEEK).unwrap(),
            false,
            breakdown_key,
            0,
        ));

        last_impression = t;
    }

    // TODO: How should we simulate a case where there are multiple conversions and impressions in between? e.g. i -> i -> c -> i -> c

    let mut last_conversion = last_impression;

    for _ in 0..conversions {
        let conversion_value = sample.conversion_value_per_ad(rng);
        let t = last_conversion + sample.conversions_time_diff(rng);

        // days_in_epoch + sample.impression_time_diff < 4 years < u8::MAX (assuming 1 epoch = 1 week)
        #[allow(clippy::cast_possible_truncation)]
        let new_epoch = epoch + (t.as_secs() / SECONDS_IN_A_WEEK) as u8;

        reports.push(GenericReport::new(
            matchkey,
            None,
            new_epoch,
            u32::try_from(t.as_secs() - u64::from(new_epoch) * SECONDS_IN_A_WEEK).unwrap(),
            true,
            0,
            conversion_value,
        ));

        last_conversion = t;
    }

    reports
}

fn gen_matchkey<R: RngCore + CryptoRng>(rng: &mut R) -> MatchKey {
    rng.gen::<MatchKey>()
}

#[cfg(test)]
mod tests {
    use super::{gen_reports, generate_events, SECONDS_IN_A_WEEK};
    use crate::sample::Sample;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::{
        cmp::Ordering,
        io::{Cursor, Write},
    };

    const DATA: &str = r#"
      {
        "devices_per_user": [
          { "index": 0, "weight": 0.0 },
          { "index": 1, "weight": 0.6 },
          { "index": 2, "weight": 0.4 }
        ],

        "cvr_per_ad": [
          { "index": { "start": 0.001, "end": 0.002 }, "weight": 0.2 },
          { "index": { "start": 0.002, "end": 0.004 }, "weight": 0.3 },
          { "index": { "start": 0.004, "end": 0.007 }, "weight": 0.3 },
          { "index": { "start": 0.007, "end": 0.01 }, "weight": 0.2 }
        ],

        "conversion_value_per_user": [
          { "index": { "start": 0, "end": 100 }, "weight": 0.3 },
          { "index": { "start": 100, "end": 1000 }, "weight": 0.6 },
          { "index": { "start": 1000, "end": 5000 }, "weight": 0.1 }
        ],

        "reach_per_ad": [
          { "index": { "start": 1, "end": 100 }, "weight": 0.1 },
          { "index": { "start": 100, "end": 1000 }, "weight": 0.2 },
          { "index": { "start": 1000, "end": 5000 }, "weight": 0.4 },
          { "index": { "start": 5000, "end": 10000 }, "weight": 0.3 }
        ],

        "impression_per_user": [
          { "index": 1, "weight": 0.9 },
          { "index": 2, "weight": 0.1 }
        ],

        "conversion_per_user": [
          { "index": 1, "weight": 0.9 },
          { "index": 2, "weight": 0.1 }
        ],

        "impression_impression_duration": [
          { "index": { "start": 1.0, "end": 2.0 }, "weight": 0.1 },
          { "index": { "start": 2.0, "end": 3.0 }, "weight": 0.2 },
          { "index": { "start": 3.0, "end": 4.0 }, "weight": 0.5 },
          { "index": { "start": 4.0, "end": 5.0 }, "weight": 0.2 }
        ],

        "impression_conversion_duration": [
          { "index": { "start": 0, "end": 1 }, "weight": 0.7 },
          { "index": { "start": 1, "end": 2 }, "weight": 0.1 },
          { "index": { "start": 2, "end": 4 }, "weight": 0.1 },
          { "index": { "start": 4, "end": 7 }, "weight": 0.1 }
        ]
      }
    "#;

    #[test]
    fn same_seed_generates_same_output() {
        let mut buf1 = Cursor::new(Vec::<u8>::new());
        let mut buf2 = Cursor::new(Vec::<u8>::new());

        let mut out1 = Box::new(&mut buf1) as Box<dyn Write>;
        let mut out2 = Box::new(&mut buf2) as Box<dyn Write>;

        let seed = Some(0);

        let config = serde_json::from_reader(&mut Cursor::new(DATA)).unwrap();
        let sample = Sample::new(&config);

        let mut rng = seed.map_or(StdRng::from_entropy(), StdRng::seed_from_u64);
        generate_events(&sample, 100, 0, &mut rng, &mut out1);

        let mut rng = seed.map_or(StdRng::from_entropy(), StdRng::seed_from_u64);
        generate_events(&sample, 100, 0, &mut rng, &mut out2);

        drop(out1);
        drop(out2);

        assert!(buf1.eq(&buf2));
    }

    #[test]
    fn epoch_rolls() {
        let seed = Some(0);

        let config = serde_json::from_reader(&mut Cursor::new(DATA)).unwrap();
        let sample = Sample::new(&config);

        let mut rng = seed.map_or(StdRng::from_entropy(), StdRng::seed_from_u64);

        let reports = gen_reports(u8::MAX, u8::MAX, 0, 0, &sample, &mut rng);

        let mut last_t = 0;
        let mut last_epoch = 0;
        for r in &reports {
            assert!(u64::from(r.timestamp) < SECONDS_IN_A_WEEK);

            match r.epoch.cmp(&last_epoch) {
                Ordering::Equal => assert!(r.timestamp > last_t),
                Ordering::Greater => assert!(r.timestamp < last_t),
                Ordering::Less => panic!("incorrect epoch"),
            }

            last_t = r.timestamp;
            last_epoch = r.epoch;
        }
    }
}
