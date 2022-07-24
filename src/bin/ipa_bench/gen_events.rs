use super::sample::Sample;
use log::{debug, info, trace};
use rand::{CryptoRng, Rng, RngCore};
use rand_distr::num_traits::ToPrimitive;
use rand_distr::{Bernoulli, Distribution};
use raw_ipa::helpers::models::{
    Event as EEvent, SecretSharable, SecretShare, SourceEvent as ESourceEvent,
    TriggerEvent as ETriggerEvent,
};
use serde::{Deserialize, Serialize};
use std::io;
use std::time::Duration;

const DAYS_IN_EPOCH: u64 = 7;
pub type MatchKey = Vec<u64>;
type Epoch = u8;

#[derive(Clone)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct EventBase {
    // For this tool, we'll fix the length of a matchkey to u64
    pub matchkeys: MatchKey,
    pub epoch: Epoch,
    pub timestamp: u32,
}

#[derive(Clone)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct SourceEvent {
    pub event: EventBase,

    /// Ad breakdown key value
    pub breakdown_key: String,
}

#[derive(Clone)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct TriggerEvent {
    pub event: EventBase,

    /// Conversion value
    pub value: u32,

    /// Zero-knowledge proof value
    pub zkp: String,
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub enum Event {
    // Source event in clear
    Source(SourceEvent),
    // Trigger event in clear
    Trigger(TriggerEvent),
    // Source event in cipher if --secret-share option is enabled
    EncryptedSource(ESourceEvent),
    // Trigger event in cipher if --secret-share option is enabled
    EncryptedTrigger(ETriggerEvent),
}

struct GenEventParams {
    devices: u8,
    impressions: u8,
    conversions: u8,
    epoch: Epoch,
    breakdown_key: String,
}

// TODO: Currently, users are mutually exclusive in each ad loop (i.e. User A in ad X will never appear in other ads).
// We need to generate events from same users across ads (but how often should a user appear in different ads?)
// "Ads" doesn't mean FB's L3 ads. It could be ads from different businesses.

pub fn generate_events<R: RngCore + CryptoRng, W: io::Write>(
    sample: &Sample,
    total_count: u32,
    epoch: Epoch,
    secret_share: bool,
    rng: &mut R,
    ss_rng: &mut R,
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
            // # of devices == # of matchkeys
            let devices = sample.devices_per_user(rng);
            trace!("devices per user: {}", devices);

            let impressions = sample.impression_per_user(rng);
            trace!("impressions per user: {}", impressions);

            // Probabilistically decide whether this user has converted or not
            let conversions = if Bernoulli::new(cvr).unwrap().sample(rng) {
                sample.conversion_per_user(rng)
            } else {
                0
            };
            trace!("conversions per user: {}", conversions);

            let events = gen_events(
                &GenEventParams {
                    devices,
                    impressions,
                    conversions,
                    epoch,
                    breakdown_key: ad_id.to_string(),
                },
                secret_share,
                sample,
                rng,
                ss_rng,
            );

            total_impressions += impressions.to_u32().unwrap();
            total_conversions += conversions.to_u32().unwrap();

            for e in events {
                // note: removed "record separator" at the beginning of each reacord due to serde failing to recognize it
                out.write_all(serde_json::to_string(&e).unwrap().as_bytes())
                    .unwrap();
                writeln!(out).unwrap();

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

fn gen_events<R: RngCore + CryptoRng>(
    params: &GenEventParams,
    secret_share: bool,
    sample: &Sample,
    rng: &mut R,
    ss_rng: &mut R,
) -> Vec<Event> {
    let mut events: Vec<Event> = Vec::new();

    let matchkeys = gen_matchkeys(params.devices, rng);
    let mut ss_mks: Vec<SecretShare> = Vec::new();

    if secret_share {
        for mk in &matchkeys {
            // Currently, all geneerated match keys are set in all source events from the same user. This is an ideal
            // scenario where all devices are used equally. In reality, however, that isn't the case. Should we pick
            // a few match keys out from the events?
            ss_mks.push(mk.xor_split(ss_rng));
        }
    }

    // Randomly choose a datetime of the first impression in [0..DAYS_IN_EPOCH)
    // TODO: Assume that impressions happen any time within the epoch
    let mut last_impression = Duration::new(rng.gen_range(0..DAYS_IN_EPOCH * 24 * 60 * 60), 0);

    for _ in 0..params.impressions {
        let t = last_impression + sample.impressions_time_diff(rng);

        if secret_share {
            events.push(Event::EncryptedSource(ESourceEvent {
                event: EEvent {
                    matchkeys: ss_mks.clone(),
                    //TODO: Carry to next epoch if timestamp > DAYS_IN_EPOCH
                    epoch: params.epoch,
                    timestamp: u32::try_from(t.as_secs()).unwrap().xor_split(ss_rng),
                },
                breakdown_key: params.breakdown_key.clone(),
            }));
        } else {
            events.push(Event::Source(SourceEvent {
                event: EventBase {
                    matchkeys: matchkeys.clone(),
                    //TODO: Carry to next epoch if timestamp > DAYS_IN_EPOCH
                    epoch: params.epoch,
                    timestamp: u32::try_from(t.as_secs()).unwrap(),
                },
                breakdown_key: params.breakdown_key.clone(),
            }));
        }

        last_impression = t;
    }

    // TODO: How should we simulate a case where there are multiple conversions and impressions in between? e.g. i -> i -> c -> i -> c

    let mut last_conversion = last_impression;

    for _ in 0..params.conversions {
        let conversion_value = sample.conversion_value_per_ad(rng);
        let t = last_conversion + sample.conversions_time_diff(rng);

        if secret_share {
            events.push(Event::EncryptedTrigger(ETriggerEvent {
                event: EEvent {
                    matchkeys: ss_mks.clone(),
                    //TODO: Carry to next epoch if timestamp > DAYS_IN_EPOCH
                    epoch: params.epoch,
                    timestamp: u32::try_from(t.as_secs()).unwrap().xor_split(ss_rng),
                },
                value: conversion_value.xor_split(ss_rng),
                zkp: String::from("zkp"),
            }));
        } else {
            events.push(Event::Trigger(TriggerEvent {
                event: EventBase {
                    matchkeys: matchkeys.clone(),
                    //TODO: Carry to next epoch if timestamp > DAYS_IN_EPOCH
                    epoch: params.epoch,
                    timestamp: u32::try_from(t.as_secs()).unwrap(),
                },
                value: conversion_value,
                zkp: String::from("zkp"),
            }));
        }

        last_conversion = t;
    }

    events
}

fn gen_matchkeys<R: RngCore + CryptoRng>(count: u8, rng: &mut R) -> MatchKey {
    let mut mks = Vec::new();

    for _ in 0..count {
        mks.push(rng.gen::<u64>());
    }
    mks
}

#[cfg(test)]
mod tests {
    use super::{generate_events, Event};
    use crate::sample::Sample;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use raw_ipa::helpers::models::SecretSharable;
    use std::io::prelude::*;
    use std::io::{BufReader, Cursor, Write};

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
        let mut ss_rng = seed.map_or(StdRng::from_entropy(), StdRng::seed_from_u64);
        generate_events(&sample, 100, 0, false, &mut rng, &mut ss_rng, &mut out1);

        let mut rng = seed.map_or(StdRng::from_entropy(), StdRng::seed_from_u64);
        let mut ss_rng = seed.map_or(StdRng::from_entropy(), StdRng::seed_from_u64);
        generate_events(&sample, 100, 0, false, &mut rng, &mut ss_rng, &mut out2);

        drop(out1);
        drop(out2);

        assert!(buf1.eq(&buf2));
    }

    #[test]
    fn same_seed_generates_same_ss_output() {
        let mut buf1 = Cursor::new(Vec::<u8>::new());
        let mut buf2 = Cursor::new(Vec::<u8>::new());

        let mut out1 = Box::new(&mut buf1) as Box<dyn Write>;
        let mut out2 = Box::new(&mut buf2) as Box<dyn Write>;

        let seed = Some(0);

        let config = serde_json::from_reader(&mut Cursor::new(DATA)).unwrap();
        let sample = Sample::new(&config);

        let mut rng = seed.map_or(StdRng::from_entropy(), StdRng::seed_from_u64);
        let mut ss_rng = seed.map_or(StdRng::from_entropy(), StdRng::seed_from_u64);
        generate_events(&sample, 100, 0, false, &mut rng, &mut ss_rng, &mut out1);

        let mut rng = seed.map_or(StdRng::from_entropy(), StdRng::seed_from_u64);
        let mut ss_rng = seed.map_or(StdRng::from_entropy(), StdRng::seed_from_u64);
        generate_events(&sample, 100, 0, false, &mut rng, &mut ss_rng, &mut out2);

        drop(out1);
        drop(out2);

        assert!(buf1.eq(&buf2));
    }

    #[test]
    fn same_seed_ss_matchkeys_and_plain_matchkeys_are_same() {
        let mut buf1 = Cursor::new(Vec::<u8>::new());
        let mut buf2 = Cursor::new(Vec::<u8>::new());

        let mut out1 = Box::new(&mut buf1) as Box<dyn Write>;
        let mut out2 = Box::new(&mut buf2) as Box<dyn Write>;

        let seed = Some(0);

        let config = serde_json::from_reader(&mut Cursor::new(DATA)).unwrap();
        let sample = Sample::new(&config);

        let mut rng = seed.map_or(StdRng::from_entropy(), StdRng::seed_from_u64);
        let mut ss_rng = seed.map_or(StdRng::from_entropy(), StdRng::seed_from_u64);
        generate_events(&sample, 10000, 0, false, &mut rng, &mut ss_rng, &mut out1);

        let mut rng = seed.map_or(StdRng::from_entropy(), StdRng::seed_from_u64);
        let mut ss_rng = seed.map_or(StdRng::from_entropy(), StdRng::seed_from_u64);
        generate_events(&sample, 10000, 0, true, &mut rng, &mut ss_rng, &mut out2);

        drop(out1);
        drop(out2);

        let buf1 = BufReader::new(buf1);
        let mut buf2 = BufReader::new(buf2);

        for line in buf1.lines() {
            let l1 = line.unwrap();
            let mut l2 = String::new();
            buf2.read_line(&mut l2).unwrap();

            let e1 = serde_json::from_str::<Event>(&l1).unwrap();
            let e2 = serde_json::from_str::<Event>(&l2).unwrap();

            match e1 {
                Event::Source(s) => {
                    if let Event::EncryptedSource(es) = e2 {
                        for (k, v) in s.event.matchkeys.iter().enumerate() {
                            let ssm = u64::combine(&es.event.matchkeys[k]).unwrap();
                            assert!(*v == ssm);
                        }

                        let timestamp = u32::combine(&es.event.timestamp).unwrap();
                        assert!(s.event.timestamp == timestamp);
                        assert!(s.breakdown_key == es.breakdown_key);
                        assert!(s.event.epoch == es.event.epoch);
                    } else {
                        unreachable!();
                    }
                }

                Event::Trigger(t) => {
                    if let Event::EncryptedTrigger(et) = e2 {
                        for (k, v) in t.event.matchkeys.iter().enumerate() {
                            let matchkey = u64::combine(&et.event.matchkeys[k]).unwrap();
                            assert!(*v == matchkey);
                        }

                        let timestamp = u32::combine(&et.event.timestamp).unwrap();
                        let value = u32::combine(&et.value).unwrap();
                        assert!(t.event.timestamp == timestamp);
                        assert!(t.value == value);
                        assert!(t.zkp == et.zkp);
                        assert!(t.event.epoch == et.event.epoch);
                    } else {
                        unreachable!();
                    }
                }

                Event::EncryptedSource(_) | Event::EncryptedTrigger(_) => unreachable!(),
            }
        }
    }
}
