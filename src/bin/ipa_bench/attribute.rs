use crate::gen_events::{Event, EventType, SourceEvent, TriggerEvent};
use log::info;
use raw_ipa::helpers::models::SecretSharable;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::io::prelude::*;
use std::time::Instant;

#[cfg_attr(feature = "enable-serde", derive(Serialize))]
struct Report {
    breakdown_key: String,
    // For this tool, we'll fix the length of a matchkey to u64
    matchkeys: Vec<u64>,
    reach: u32,
    impressions: u32,
    conversions: u32,
    total_value: u32,
}

impl Report {
    fn new(key: &str) -> Self {
        Report {
            breakdown_key: String::from(key),
            matchkeys: Vec::new(),
            reach: 0,
            impressions: 0,
            conversions: 0,
            total_value: 0,
        }
    }
}

pub fn generate_report(
    input: &mut Box<dyn io::Read>,
    attribution_window: u32,
    model: &str,
    out: &mut Box<dyn io::Write>,
) {
    let reports = gen_report_impl(input, attribution_window, model);

    // CSV, for now. We can add --output-format option in the future
    writeln!(out, "breakdown_key,reach,impressions,conversions,values").unwrap();
    for r in &reports {
        writeln!(
            out,
            "{},{},{},{},{}",
            r.breakdown_key, r.reach, r.impressions, r.conversions, r.total_value
        )
        .unwrap();
    }
}

fn gen_report_impl(
    input: &mut Box<dyn io::Read>,
    attribution_window: u32,
    model: &str,
) -> Vec<Report> {
    let buf = io::BufReader::new(input);

    let mut events: Vec<EventType> = Vec::new();

    let start = Instant::now();

    // 1. Sort matchkeys in each event. Everything in memory for now
    for line in buf.lines() {
        let l = line.unwrap();
        if l.trim().is_empty() {
            continue;
        }

        let event = serde_json::from_str::<EventType>(l.trim()).unwrap();

        match event {
            EventType::S(mut s) => {
                s.event.matchkeys.sort_unstable();
                events.push(EventType::S(s));
            }

            EventType::ES(es) => {
                let mut mks: Vec<u64> = es
                    .event
                    .matchkeys
                    .iter()
                    .map(|x| u64::combine(x).unwrap())
                    .collect();
                let timestamp = u32::combine(&es.event.timestamp).unwrap();

                mks.sort_unstable();
                events.push(EventType::S(SourceEvent {
                    event: Event {
                        matchkeys: mks,
                        epoch: es.event.epoch,
                        timestamp,
                    },
                    breakdown_key: es.breakdown_key,
                }));
            }

            EventType::T(mut t) => {
                t.event.matchkeys.sort_unstable();
                events.push(EventType::T(t));
            }

            EventType::ET(et) => {
                let mut mks: Vec<u64> = et
                    .event
                    .matchkeys
                    .iter()
                    .map(|x| u64::combine(x).unwrap())
                    .collect();
                let timestamp = u32::combine(&et.event.timestamp).unwrap();
                let value = u32::combine(&et.value).unwrap();

                mks.sort_unstable();
                events.push(EventType::T(TriggerEvent {
                    event: Event {
                        matchkeys: mks,
                        epoch: et.event.epoch,
                        timestamp,
                    },
                    value,
                    zkp: et.zkp,
                }));
            }
        }
    }

    let duration = start.elapsed();
    info!("Deserialize: {:?}", duration);

    let start = Instant::now();

    // 2. Sort all events by first matchkey, epoch and timestamp
    events.sort_unstable_by_key(|k| {
        let e = match k {
            EventType::S(s) => Ok(&s.event),
            EventType::T(t) => Ok(&t.event),
            _ => Err(()),
        }
        .unwrap();

        (e.matchkeys[0], e.epoch, e.timestamp)
    });

    let duration = start.elapsed();
    info!("Sort: {:?}", duration);

    let start = Instant::now();

    // 3. Attribution
    let reports = match model {
        "LastTouch" => last_n_attribution(1, &events, attribution_window),
        _ => Vec::new(),
    };

    let duration = start.elapsed();
    info!("Match: {:?}", duration);

    reports
}

fn last_n_attribution(n: usize, events: &[EventType], attribution_window: u32) -> Vec<Report> {
    let mut attribution_table: HashMap<String, Report> = HashMap::new();
    let mut last_n_events: VecDeque<&SourceEvent> = VecDeque::with_capacity(n);

    // For each event (sorted by matchkeys, epoch, timestamp), do the followings:
    // 0. If the breakdown_key doesn't exist in [attribution_table], create a new entry
    // 1. Increment the impression by 1
    // 2. If the user's matchkeys don't exist in the report for this breakdown_key, add them. Increment the reach by 1
    // 3. If a trigger event following a source event and within the given attribution window, increment the conversion by 1. Add the conversion value.

    for e in events {
        match e {
            EventType::S(s) => {
                if !attribution_table.contains_key(s.breakdown_key.as_str()) {
                    attribution_table.insert(
                        s.breakdown_key.clone(),
                        Report::new(s.breakdown_key.as_str()),
                    );
                }

                let report = attribution_table.get_mut(s.breakdown_key.as_str()).unwrap();

                report.impressions += 1;

                if !s
                    .event
                    .matchkeys
                    .iter()
                    .any(|x| report.matchkeys.contains(x))
                {
                    report.reach += 1;
                    report
                        .matchkeys
                        .extend_from_slice(s.event.matchkeys.as_slice());
                }

                // Same breakdown_key event will be removed and pushed to the front. This ensures all events in the queue have unique breakdown keys
                last_n_events.retain(|x| x.breakdown_key != s.breakdown_key);
                if last_n_events.len() == n {
                    last_n_events.pop_back();
                }
                last_n_events.push_front(s);
            }

            EventType::T(t) => {
                for e in &last_n_events {
                    if t.event.matchkeys.iter().any(|x| {
                        e.event.matchkeys.contains(x)
                        // TODO: Epoch diff
                            && (t.event.timestamp - e.event.timestamp < attribution_window * 86400)
                    }) {
                        let report = attribution_table.get_mut(e.breakdown_key.as_str()).unwrap();

                        report.conversions += 1;
                        report.total_value += t.value;
                    }
                }
            }

            _ => {}
        }
    }

    attribution_table.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::gen_report_impl;
    use std::io::{Cursor, Read};

    #[test]
    fn last_touch_7_days_attribution() {
        // SourceEvent timestamp = 0
        // TriggerEvent timestamp = 604799 secs (6 days 23 hours 59 mins 59 secs) < 7-day attribution window
        const TEST_INPUT: &str = r#"
        {"S":{"event":{"matchkeys":[88888888],"epoch":0,"timestamp":0},"breakdown_key":"12345"}}
        {"T":{"event":{"matchkeys":[88888888],"epoch":0,"timestamp":604799},"value":100,"zkp":"zkp"}}
        "#;

        let events = Vec::from(TEST_INPUT);
        let mut input: Box<dyn Read> = Box::new(Cursor::new(events));
        let reports = gen_report_impl(&mut input, 7, "LastTouch");

        assert!(reports.len() == 1);
        assert!(reports[0].breakdown_key == "12345");
        assert!(reports[0].reach == 1);
        assert!(reports[0].impressions == 1);
        assert!(reports[0].conversions == 1);
        assert!(reports[0].total_value == 100);
    }

    #[test]
    fn multiple_impressions_multiple_reach() {
        const TEST_INPUT: &str = r#"
        {"S":{"event":{"matchkeys":[88888888],"epoch":0,"timestamp":0},"breakdown_key":"12345"}}
        {"T":{"event":{"matchkeys":[88888888],"epoch":0,"timestamp":604799},"value":100,"zkp":"zkp"}}
        {"S":{"event":{"matchkeys":[99999999],"epoch":0,"timestamp":1},"breakdown_key":"12345"}}
        "#;

        let events = Vec::from(TEST_INPUT);
        let mut input: Box<dyn Read> = Box::new(Cursor::new(events));
        let reports = gen_report_impl(&mut input, 7, "LastTouch");

        assert!(reports.len() == 1);
        assert!(reports[0].breakdown_key == "12345");
        assert!(reports[0].reach == 2);
        assert!(reports[0].impressions == 2);
        assert!(reports[0].conversions == 1);
        assert!(reports[0].total_value == 100);
    }

    #[test]
    fn multiple_impressions_unique_reach() {
        const TEST_INPUT: &str = r#"
        {"S":{"event":{"matchkeys":[88888888],"epoch":0,"timestamp":0},"breakdown_key":"12345"}}
        {"S":{"event":{"matchkeys":[88888888],"epoch":0,"timestamp":0},"breakdown_key":"12345"}}
        {"T":{"event":{"matchkeys":[88888888],"epoch":0,"timestamp":604799},"value":100,"zkp":"zkp"}}
        "#;

        let events = Vec::from(TEST_INPUT);
        let mut input: Box<dyn Read> = Box::new(Cursor::new(events));
        let reports = gen_report_impl(&mut input, 7, "LastTouch");

        assert!(reports.len() == 1);
        assert!(reports[0].breakdown_key == "12345");
        assert!(reports[0].reach == 1);
        assert!(reports[0].impressions == 2);
        assert!(reports[0].conversions == 1);
        assert!(reports[0].total_value == 100);
    }

    #[test]
    fn same_user_multiple_breakdown_keys() {
        const TEST_INPUT: &str = r#"
        {"S":{"event":{"matchkeys":[88888888],"epoch":0,"timestamp":0},"breakdown_key":"67890"}}
        {"S":{"event":{"matchkeys":[88888888],"epoch":0,"timestamp":100},"breakdown_key":"12345"}}
        {"S":{"event":{"matchkeys":[88888888],"epoch":0,"timestamp":200},"breakdown_key":"67890"}}
        {"S":{"event":{"matchkeys":[88888888],"epoch":0,"timestamp":300},"breakdown_key":"abcde"}}
        {"T":{"event":{"matchkeys":[88888888],"epoch":0,"timestamp":604799},"value":100,"zkp":"zkp"}}
        "#;

        let events = Vec::from(TEST_INPUT);
        let mut input: Box<dyn Read> = Box::new(Cursor::new(events));
        let reports = gen_report_impl(&mut input, 7, "LastTouch");

        assert!(reports.len() == 3);

        for r in &reports {
            match r.breakdown_key.as_str() {
                "12345" => {
                    assert!(r.reach == 1);
                    assert!(r.impressions == 1);
                    assert!(r.conversions == 0);
                    assert!(r.total_value == 0);
                }
                "67890" => {
                    assert!(r.reach == 1);
                    assert!(r.impressions == 2);
                    assert!(r.conversions == 0);
                    assert!(r.total_value == 0);
                }
                "abcde" => {
                    assert!(r.reach == 1);
                    assert!(r.impressions == 1);
                    assert!(r.conversions == 1);
                    assert!(r.total_value == 100);
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn multiple_conversions_same_breakdown_key() {
        // The 3rd trigger event is outside of 7-day attribution window
        const TEST_INPUT: &str = r#"
        {"S":{"event":{"matchkeys":[88888888],"epoch":0,"timestamp":0},"breakdown_key":"12345"}}
        {"S":{"event":{"matchkeys":[88888888],"epoch":0,"timestamp":100},"breakdown_key":"12345"}}
        {"T":{"event":{"matchkeys":[88888888],"epoch":0,"timestamp":604799},"value":100,"zkp":"zkp"}}
        {"T":{"event":{"matchkeys":[88888888],"epoch":0,"timestamp":604899},"value":100,"zkp":"zkp"}}
        {"T":{"event":{"matchkeys":[88888888],"epoch":0,"timestamp":604900},"value":100,"zkp":"zkp"}}
        "#;

        let events = Vec::from(TEST_INPUT);
        let mut input: Box<dyn Read> = Box::new(Cursor::new(events));
        let reports = gen_report_impl(&mut input, 7, "LastTouch");

        assert!(reports.len() == 1);
        assert!(reports[0].breakdown_key == "12345");
        assert!(reports[0].reach == 1);
        assert!(reports[0].impressions == 2);
        assert!(reports[0].conversions == 2);
        assert!(reports[0].total_value == 200);
    }

    #[test]
    fn outside_attribution_window() {
        // SourceEvent timestamp = 0
        // TriggerEvent timestamp = 604800 secs (7 days) >=  7-day attribution window
        const TEST_INPUT: &str = r#"
        {"S":{"event":{"matchkeys":[88888888],"epoch":0,"timestamp":0},"breakdown_key":"12345"}}
        {"T":{"event":{"matchkeys":[88888888],"epoch":0,"timestamp":604800},"value":100,"zkp":"zkp"}}
        "#;

        let events = Vec::from(TEST_INPUT);
        let mut input: Box<dyn Read> = Box::new(Cursor::new(events));
        let reports = gen_report_impl(&mut input, 7, "LastTouch");

        assert!(reports.len() == 1);
        assert!(reports[0].breakdown_key == "12345");
        assert!(reports[0].reach == 1);
        assert!(reports[0].impressions == 1);
        assert!(reports[0].conversions == 0);
        assert!(reports[0].total_value == 0);
    }

    #[test]
    fn multiple_users_no_dupe_counts() {
        // 1 source and 1 trigger events from user 88888888
        // 2 trigger events from user 99999999. No corresponding source event
        const TEST_INPUT: &str = r#"
        {"S":{"event":{"matchkeys":[88888888],"epoch":0,"timestamp":0},"breakdown_key":"12345"}}
        {"T":{"event":{"matchkeys":[88888888],"epoch":0,"timestamp":604799},"value":100,"zkp":"zkp"}}
        {"T":{"event":{"matchkeys":[99999999],"epoch":0,"timestamp":0},"value":100,"zkp":"zkp"}}
        {"T":{"event":{"matchkeys":[99999999],"epoch":0,"timestamp":604800},"value":100,"zkp":"zkp"}}
        "#;

        let events = Vec::from(TEST_INPUT);
        let mut input: Box<dyn Read> = Box::new(Cursor::new(events));
        let reports = gen_report_impl(&mut input, 7, "LastTouch");

        assert!(reports.len() == 1);
        assert!(reports[0].breakdown_key == "12345");
        assert!(reports[0].reach == 1);
        assert!(reports[0].impressions == 1);
        assert!(reports[0].conversions == 1);
        assert!(reports[0].total_value == 100);
    }
}
