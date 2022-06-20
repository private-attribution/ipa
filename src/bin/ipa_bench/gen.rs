use super::sample::Sample;
use byteorder::ByteOrder;
use chrono::Duration;
use log::{debug, info, trace};
use rand::SeedableRng;
use rand::{CryptoRng, Rng, RngCore};
use rand_chacha::ChaCha20Rng;
use rand_distr::{num_traits::ToPrimitive, Bernoulli, Distribution};
use raw_ipa::helpers::models::{
    Event as EEvent, SecretShare, SourceEvent as ESourceEvent, TriggerEvent as ETriggerEvent,
};
use serde::{Deserialize, Serialize};
use std::io;

const DAYS_IN_EPOCH: i64 = 7;

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
struct Event {
    matchkeys: Vec<u64>,
    epoch: u8,
    timestamp: u64,
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
struct SourceEvent {
    event: Event,
    breakdown_key: String,
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
struct TriggerEvent {
    event: Event,
    value: u32,
    zkp: String,
}

enum EventType {
    S(SourceEvent),
    T(TriggerEvent),
    ES(ESourceEvent),
    ET(ETriggerEvent),
}

// TODO: Currently, users are mutually exclusive in each ad loop (i.e. User A in ad X will never appear in other ads).
// We need to generate events from same users across ads (but how often should a user appear in different ads?)
// "Ads" doesn't mean FB's L3 ads. It could be ads from different businesses.

pub fn generate_events(
    total_count: u32,
    epoch: u8,
    secret_share: bool,
    seed: &Option<u64>,
    out: &mut Box<dyn io::Write>,
) -> (u32, u32) {
    let mut rng = match seed {
        None => ChaCha20Rng::from_entropy(),
        Some(seed) => ChaCha20Rng::seed_from_u64(*seed),
    };
    debug!("seed: {:?}", rng.get_seed());

    // Separate RNG for generating secret shares
    let mut ss_rng = match seed {
        None => ChaCha20Rng::from_entropy(),
        Some(seed) => ChaCha20Rng::seed_from_u64(*seed),
    };

    let sample = Sample::new();

    let mut ad_count = 0;
    let mut event_count = 0;
    let mut s_count = 0;
    let mut t_count = 0;

    // Simulate impressions and conversions from an ad.
    // We define "ad" as a group of impressions and conversions from targeted users who are selected by predefined
    // breakdowns such as age, gender and locations.
    loop {
        ad_count += 1;
        debug!("ad: {}", ad_count);

        // TODO: 99.97% queries in ads manager account for L1-3 breakdown only. For now, we'll do 1 ad = 1 breakdown key
        let ad_id: u32 = rng.gen();

        // Number of unique people who saw the ad
        let reach = sample.reach_per_ad(&mut rng);
        debug!("reach: {}", reach);

        // CVR for the ad
        let cvr = sample.cvr_per_ad_account(&mut rng);
        debug!("CVR: {}", cvr);

        for _ in 0..reach {
            // # of devices == # of matchkeys
            let devices = sample.devices_per_user(&mut rng);
            trace!("devices per user: {}", devices);

            let impressions = sample.impression_per_user(&mut rng);
            trace!("impressions per user: {}", impressions);

            // Probabilistically decide whether this user has converted or not
            let conversions = if Bernoulli::new(cvr).unwrap().sample(&mut rng) {
                sample.conversion_per_user(&mut rng)
            } else {
                0
            };
            trace!("conversions per user: {}", conversions);

            let events = gen_events(
                devices,
                impressions,
                conversions,
                epoch,
                &ad_id.to_string(),
                secret_share,
                &sample,
                &mut rng,
                &mut ss_rng,
            );

            for e in events {
                let json_string = match e {
                    EventType::S(s) => {
                        s_count += 1;
                        serde_json::to_string(&s).unwrap()
                    }
                    EventType::ES(s) => {
                        s_count += 1;
                        serde_json::to_string(&s).unwrap()
                    }
                    EventType::T(t) => {
                        t_count += 1;
                        serde_json::to_string(&t).unwrap()
                    }
                    EventType::ET(t) => {
                        t_count += 1;
                        serde_json::to_string(&t).unwrap()
                    }
                };

                out.write_all(json_string.as_bytes()).unwrap();
                writeln!(out).unwrap();

                event_count += 1;
                if event_count % 10000 == 0 {
                    info!("{}", event_count);
                }
                if event_count >= total_count {
                    return (s_count, t_count);
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn gen_events<R: RngCore + CryptoRng>(
    devices: u8,
    impressions: u8,
    conversions: u8,
    epoch: u8,
    breakdown_key: &str,
    secret_share: bool,
    sample: &Sample,
    rng: &mut R,
    ss_rng: &mut R,
) -> Vec<EventType> {
    let mut events: Vec<EventType> = Vec::new();

    let matchkeys = gen_matchkeys(devices, rng);
    let mut ss_mks: Vec<SecretShare> = Vec::new();

    if secret_share {
        for mk in &matchkeys {
            let mut bytes = [0; 8];
            byteorder::BigEndian::write_u64(&mut bytes, *mk);

            // Currently, all geneerated match keys are set in all source events from the same user. This is an ideal
            // scenario where all devices are used equally. In reality, however, that isn't the case. Should we pick
            // a few match keys out from the events?
            ss_mks.push(to_secret_share(&bytes, ss_rng));
        }
    }

    // Randomly choose a datetime of the first impression
    // TODO: Assume that impressions happen any time within 0-6 days into epoch
    let mut last_impression = Duration::days(rng.gen_range(0..DAYS_IN_EPOCH - 1))
        + Duration::hours(rng.gen_range(0..23))
        + Duration::minutes(rng.gen_range(0..59))
        + Duration::seconds(rng.gen_range(0..59));
    trace!(
        "ad created at epoch + {}d {}h {}m {}s",
        last_impression.num_days(),
        last_impression.num_hours() - last_impression.num_days() * 24,
        last_impression.num_minutes() - last_impression.num_hours() * 60,
        last_impression.num_seconds() - last_impression.num_minutes() * 60,
    );

    for _ in 0..impressions {
        let t = last_impression + sample.impressions_time_diff(rng);

        if secret_share {
            events.push(EventType::ES(ESourceEvent {
                event: EEvent {
                    matchkeys: ss_mks.clone(),
                    epoch,
                    timestamp: to_secret_share(&t.num_seconds().to_be_bytes(), ss_rng),
                },
                breakdown_key: String::from(breakdown_key),
            }));
        } else {
            events.push(EventType::S(SourceEvent {
                event: Event {
                    matchkeys: matchkeys.clone(),
                    epoch,
                    timestamp: t.num_seconds().to_u64().unwrap(),
                },
                breakdown_key: String::from(breakdown_key),
            }));
        }

        last_impression = t;
    }

    // TODO: How should we simulate a case where there are multiple conversions and impressions in between? e.g. i -> i -> c -> i -> c

    let mut last_conversion = last_impression;

    for _ in 0..conversions {
        let conversion_value = sample.conversion_value_per_ad(rng);

        // TODO: Need to make sure the time is > SourceEvent.timestamp + imp_cv_interval_distribution
        let t = last_conversion + sample.conversions_time_diff(rng);

        if secret_share {
            events.push(EventType::ET(ETriggerEvent {
                event: EEvent {
                    matchkeys: ss_mks.clone(),
                    epoch,
                    timestamp: to_secret_share(&t.num_seconds().to_be_bytes(), ss_rng),
                },
                value: to_secret_share(&conversion_value.to_be_bytes(), ss_rng),
                zkp: String::from("zkp"),
            }));
        } else {
            events.push(EventType::T(TriggerEvent {
                event: Event {
                    matchkeys: matchkeys.clone(),
                    epoch,
                    timestamp: t.num_seconds().to_u64().unwrap(),
                },
                value: conversion_value,
                zkp: String::from("zkp"),
            }));
        }

        last_conversion = t;
    }

    events
}

fn gen_matchkeys<R: RngCore + CryptoRng>(count: u8, rng: &mut R) -> Vec<u64> {
    let mut mks = Vec::new();

    for _ in 0..count {
        mks.push(rng.gen::<u64>());
    }
    mks
}

fn to_secret_share<R: RngCore + CryptoRng>(data: &[u8], rng: &mut R) -> SecretShare {
    let mut ss: SecretShare = [Vec::new(), Vec::new(), Vec::new()];

    for x in data {
        let ss1 = rng.gen::<u8>();
        let ss2 = rng.gen::<u8>();
        let ss3 = ss1 ^ ss2 ^ x;

        ss[0].push(ss1);
        ss[1].push(ss2);
        ss[2].push(ss3);
    }
    ss
}

#[cfg(test)]
mod tests {
    use byteorder::{BigEndian, ReadBytesExt};
    use raw_ipa::helpers::models::SecretShare;
    use std::fs::{self, File};
    use std::io::prelude::*;
    use std::io::{BufReader, Read, Write};
    use uuid::Uuid;

    use crate::gen::{ESourceEvent, ETriggerEvent, SourceEvent, TriggerEvent};

    use super::generate_events;

    fn from_secret_share_to_u64(ss: &SecretShare) -> u64 {
        ss[0].as_slice().read_u64::<BigEndian>().unwrap()
            ^ ss[1].as_slice().read_u64::<BigEndian>().unwrap()
            ^ ss[2].as_slice().read_u64::<BigEndian>().unwrap()
    }

    fn from_secret_share_to_u32(ss: &SecretShare) -> u32 {
        ss[0].as_slice().read_u32::<BigEndian>().unwrap()
            ^ ss[1].as_slice().read_u32::<BigEndian>().unwrap()
            ^ ss[2].as_slice().read_u32::<BigEndian>().unwrap()
    }

    #[test]
    fn same_seed_geenrates_same_output() {
        let temp1 = Uuid::new_v4().to_string();
        let temp2 = Uuid::new_v4().to_string();

        let seed = Some(0);
        let mut out1 = Box::new(File::create(&temp1).unwrap()) as Box<dyn Write>;
        let mut out2 = Box::new(File::create(&temp2).unwrap()) as Box<dyn Write>;

        generate_events(100, 0, false, &seed, &mut out1);
        generate_events(100, 0, false, &seed, &mut out2);

        let mut file1 = File::open(&temp1).unwrap();
        let mut file2 = File::open(&temp2).unwrap();
        let mut buf1 = Vec::new();
        let mut buf2 = Vec::new();

        file1.read_to_end(&mut buf1).unwrap();
        file2.read_to_end(&mut buf2).unwrap();

        assert!(buf1.eq(&buf2));

        fs::remove_file(&temp1).unwrap();
        fs::remove_file(&temp2).unwrap();
    }

    #[test]
    fn same_seed_generates_same_ss_output() {
        let temp1 = Uuid::new_v4().to_string();
        let temp2 = Uuid::new_v4().to_string();

        let seed = Some(0);
        let mut out1 = Box::new(File::create(&temp1).unwrap()) as Box<dyn Write>;
        let mut out2 = Box::new(File::create(&temp2).unwrap()) as Box<dyn Write>;

        generate_events(100, 0, false, &seed, &mut out1);
        generate_events(100, 0, false, &seed, &mut out2);

        let mut file1 = File::open(&temp1).unwrap();
        let mut file2 = File::open(&temp2).unwrap();
        let mut buf1 = Vec::new();
        let mut buf2 = Vec::new();

        file1.read_to_end(&mut buf1).unwrap();
        file2.read_to_end(&mut buf2).unwrap();

        assert!(buf1.eq(&buf2));

        fs::remove_file(&temp1).unwrap();
        fs::remove_file(&temp2).unwrap();
    }

    #[test]
    fn same_seed_ss_matchkeys_and_plain_matchkeys_are_same() {
        let temp1 = Uuid::new_v4().to_string();
        let temp2 = Uuid::new_v4().to_string();

        let seed = Some(0);
        let mut out1 = Box::new(File::create(&temp1).unwrap()) as Box<dyn Write>;
        let mut out2 = Box::new(File::create(&temp2).unwrap()) as Box<dyn Write>;

        generate_events(10000, 0, false, &seed, &mut out1);
        generate_events(10000, 0, true, &seed, &mut out2);

        let file1 = File::open(&temp1).unwrap();
        let file2 = File::open(&temp2).unwrap();
        let buf1 = BufReader::new(file1);
        let mut buf2 = BufReader::new(file2);

        for line in buf1.lines() {
            let l1 = line.unwrap();

            // Try to deserialize a line of text to SourceEvent
            let result = serde_json::from_str::<SourceEvent>(&l1);
            if let Ok(s) = result {
                // Source Event

                // Read from the second file (SS matchkeys) and deserialize
                let mut l2 = String::new();
                buf2.read_line(&mut l2).unwrap();
                let es = serde_json::from_str::<ESourceEvent>(l2.as_str()).unwrap();

                for (k, v) in s.event.matchkeys.iter().enumerate() {
                    let ssm = from_secret_share_to_u64(&es.event.matchkeys[k]);
                    assert!(*v == ssm);
                }

                let sst = from_secret_share_to_u64(&es.event.timestamp);
                assert!(s.event.timestamp == sst);
                assert!(s.breakdown_key == es.breakdown_key);
                assert!(s.event.epoch == es.event.epoch);
            } else {
                // Trigger Event
                let t = serde_json::from_str::<TriggerEvent>(&l1).unwrap();

                // Read from the second file (SS matchkeys) and deserialize
                let mut l2 = String::new();
                buf2.read_line(&mut l2).unwrap();
                let et = serde_json::from_str::<ETriggerEvent>(l2.as_str()).unwrap();

                for (k, v) in t.event.matchkeys.iter().enumerate() {
                    let matchkey = from_secret_share_to_u64(&et.event.matchkeys[k]);
                    assert!(*v == matchkey);
                }

                let timestamp = from_secret_share_to_u64(&et.event.timestamp);
                let value = from_secret_share_to_u32(&et.value);
                assert!(t.event.timestamp == timestamp);
                assert!(t.value == value);
                assert!(t.zkp == et.zkp);
                assert!(t.event.epoch == et.event.epoch);
            }
        }

        fs::remove_file(&temp1).unwrap();
        fs::remove_file(&temp2).unwrap();
    }
}
