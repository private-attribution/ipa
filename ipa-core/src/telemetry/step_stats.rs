//!
//! Export metrics collected during protocol run in CSV format. Metrics are partitioned by step.

use std::{
    collections::{BTreeMap, HashMap},
    io,
    io::{Error, Write},
};

use crate::telemetry::{
    labels,
    metrics::{
        BYTES_SENT, INDEXED_PRSS_GENERATED, RECORDS_SENT, SEQUENTIAL_PRSS_GENERATED, STEP_NARROWED,
    },
    stats::Metrics,
};

pub trait CsvExporter {
    /// Writes the serialized version of this instance into the provided writer in CSV format.
    ///
    /// ## Errors
    /// Returns an error if an IO error occurs while writing to `W`.
    fn export<W: io::Write>(&self, w: &mut W) -> Result<(), io::Error>;
}

impl CsvExporter for Metrics {
    fn export<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        // first thing is to collect all the steps and metrics emitted
        let mut steps_stats = StepsStats::default();
        for (counter_name, details) in &self.counters {
            if let Some(steps) = details.dimensions.get(labels::STEP) {
                for (step, val) in steps {
                    steps_stats.offer(step, counter_name.as_str(), *val);
                }
            }
        }

        // then dump them to the provided Write interface
        // TODO: include role dimension. That requires rethinking `Metrics` implementation
        // because it does not allow such breakdown atm.
        writeln!(
            w,
            "Step,Records sent,Bytes sent,Indexed PRSS,Sequential PRSS,Step narrowed"
        )?;
        for (step, stats) in steps_stats.all_steps() {
            writeln!(
                w,
                "{},{},{},{},{},{}",
                step,
                stats.get(RECORDS_SENT),
                stats.get(BYTES_SENT),
                stats.get(INDEXED_PRSS_GENERATED),
                stats.get(SEQUENTIAL_PRSS_GENERATED),
                stats.get(STEP_NARROWED),
            )?;
        }

        Ok(())
    }
}

#[derive(Default)]
struct StepsStats<'a> {
    inner: BTreeMap<&'a str, StepStats<'a>>,
}

impl<'a> StepsStats<'a> {
    pub fn offer(&mut self, step_name: &'a str, metric: &'a str, val: u64) {
        if let Some(step_stats) = self.inner.get_mut(step_name) {
            step_stats.offer(metric, val);
        } else {
            let mut step_stats = StepStats::default();
            step_stats.offer(metric, val);
            self.inner.insert(step_name, step_stats);
        }
    }

    pub fn all_steps(&'a self) -> impl Iterator<Item = (&'a str, &'a StepStats<'a>)> {
        self.inner.iter().map(|(k, v)| (*k, v))
    }
}

#[derive(Default)]
struct StepStats<'a> {
    inner: HashMap<&'a str, u64>,
}

impl<'a> StepStats<'a> {
    fn offer(&mut self, metric_name: &'a str, val: u64) {
        if let Some(v) = self.inner.get_mut(metric_name) {
            *v += val;
        } else {
            self.inner.insert(metric_name, val);
        }
    }

    fn get(&'a self, metric_name: &'a str) -> u64 {
        *self.inner.get(metric_name).unwrap_or(&0)
    }
}
