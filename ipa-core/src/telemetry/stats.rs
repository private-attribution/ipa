use std::{
    collections::{hash_map::Iter, HashMap},
    fmt::Debug,
};

use metrics::{KeyName, Label, SharedString};
use metrics_util::{
    debugging::{DebugValue, Snapshot},
    CompositeKey, MetricKind,
};

use crate::{helpers::Role, protocol::Gate, telemetry::labels};

/// Simple counter stats
#[derive(Debug, Default)]
pub struct CounterDetails {
    pub total_value: u64,
    pub dimensions: HashMap<SharedString, HashMap<SharedString, u64>>,
}

/// Container for metrics, their descriptions and values they've accumulated.
/// Currently only support `Counter`, however `Gauge` and `Histogram` can be easily added later.
///
/// An example of a counter layout inside this struct
/// `counter_name` -> (`total_value`: X, `dimensions`: (Y -> X1, Y -> X2))
/// total value represents the counter value, i.e. how many times this value was incremented
/// through the duration of the program, regardless of the circumstances (dimensions).
///
/// Each counter may have multiple dimensions. A dimension is a simple key-value pair that adds
/// some extra information to the counter and can be used to filter out values. For example,
/// adding `http_method` dimension allows to have a breakdown for values incremented during GET,PUT
/// or POST requests.
///
/// X1 and X2 cannot be greater than X, but these values may overlap, i.e. X1 + X2 >= X
pub struct Metrics {
    pub counters: HashMap<KeyName, CounterDetails>,
    pub metric_description: HashMap<KeyName, SharedString>,
}

impl CounterDetails {
    pub fn add(&mut self, key: &CompositeKey, val: &DebugValue) {
        let DebugValue::Counter(val) = val else {
            unreachable!()
        };
        for label in key.key().labels() {
            let (label_key, label_val) = label.clone().into_parts();
            let dimension_values = self.dimensions.entry(label_key).or_default();

            *dimension_values.entry(label_val).or_insert(0) += val;
        }

        self.total_value += val;
    }

    #[must_use]
    pub fn iter(&self) -> Iter<'_, SharedString, HashMap<SharedString, u64>> {
        self.dimensions.iter()
    }
}

impl<'a> IntoIterator for &'a CounterDetails {
    type Item = <Self::IntoIter as Iterator>::Item;
    type IntoIter = Iter<'a, SharedString, HashMap<SharedString, u64>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Metrics {
    pub fn from_snapshot(snapshot: Snapshot) -> Self {
        const ALWAYS_TRUE: fn(&[Label]) -> bool = |_| true;
        Self::with_filter(snapshot, ALWAYS_TRUE)
    }

    /// Consumes the provided snapshot and filters out metrics that don't satisfy `filter_fn`
    /// conditions.
    #[must_use]
    pub fn with_filter<F: Fn(&[Label]) -> bool>(snapshot: Snapshot, filter_fn: F) -> Self {
        let mut this = Metrics {
            counters: HashMap::new(),
            metric_description: HashMap::new(),
        };

        let snapshot = snapshot.into_vec();
        for (ckey, _, descr, val) in snapshot {
            let (key_name, labels) = ckey.key().clone().into_parts();
            if !filter_fn(labels.as_slice()) {
                continue;
            }
            let entry = this.counters.entry(key_name.clone()).or_default();

            if let Some(descr) = descr {
                this.metric_description.insert(key_name, descr);
            }

            match ckey.kind() {
                MetricKind::Counter => entry.add(&ckey, &val),
                MetricKind::Gauge | MetricKind::Histogram => unimplemented!(),
            }
        }

        this
    }

    #[must_use]
    pub fn get_counter(&self, name: &'static str) -> u64 {
        self.counters
            .get::<KeyName>(&name.into())
            .map_or(0, |details| details.total_value)
    }

    /// Creates a new assertion object that later can be used to validate assumptions about the
    /// given metric
    ///
    /// ## Panics
    /// Panics if metric does not exist in the snapshot
    #[must_use]
    pub fn assert_metric(&self, name: &'static str) -> MetricAssertion {
        let details = self
            .counters
            .get::<KeyName>(&name.into())
            .unwrap_or_else(|| panic!("{name} metric does not exist in the snapshot"));
        MetricAssertion {
            name,
            snapshot: details,
        }
    }

    /// Dumps the stats to the provided Write interface.
    ///
    /// ## Errors
    /// returns an IO error if it fails to write to the provided writer.
    pub fn print(&self, w: &mut impl std::io::Write) -> Result<(), std::io::Error> {
        let mut metrics_table = comfy_table::Table::new();
        metrics_table.set_header(vec!["metric", "description", "value", "dimensions"]);

        for (key_name, counter_stats) in &self.counters {
            let mut dim_cell_content = String::new();
            for (dim, values) in counter_stats {
                dim_cell_content += format!("{dim}\n").as_str();
                for (dim_value, &counter_val) in values {
                    dim_cell_content += format!("{dim_value} = {counter_val}\n").as_str();
                }
            }

            metrics_table.add_row(vec![
                key_name.as_str(),
                self.metric_description
                    .get(key_name)
                    .unwrap_or(&SharedString::from("")),
                counter_stats.total_value.to_string().as_str(),
                dim_cell_content.as_str(),
            ]);
        }

        if metrics_table.row_iter().len() > 0 {
            writeln!(w, "{metrics_table}")?;
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct MetricAssertion<'a> {
    name: &'static str,
    snapshot: &'a CounterDetails,
}

#[allow(clippy::return_self_not_must_use)]
impl<'a> MetricAssertion<'a> {
    /// Validates metric total value (i.e. ignoring dimensionality)
    /// ## Panics
    /// Panics if value is not equal to expected
    pub fn total<I: TryInto<u64>>(&self, expected: I) -> Self {
        let expected = expected.try_into().ok().unwrap();
        let actual = self.snapshot.total_value;
        assert_eq!(
            expected, actual,
            "expected {} to be emitted exactly {expected} times, got {actual}",
            self.name
        );
        self.clone()
    }

    /// Validates metric value per step dimension.
    /// ## Panics
    /// Panics if value is not equal to expected
    pub fn per_step<I: TryInto<u64>>(&self, gate: &Gate, expected: I) -> Self {
        let actual = self.get_dimension(labels::STEP).get(gate.as_ref()).copied();

        let expected = expected.try_into().ok();

        assert_eq!(expected, actual);
        self.clone()
    }

    /// Validates metric value per helper dimension.
    /// ## Panics
    /// Panics if value is not equal to expected
    pub fn per_helper<I: TryInto<u64>>(&self, role: &Role, expected: I) -> Self {
        let actual = self.get_dimension(labels::ROLE).get(role.as_ref()).copied();
        let expected = expected.try_into().ok();

        assert_eq!(expected, actual);
        self.clone()
    }

    fn get_dimension(&self, name: &'static str) -> &HashMap<SharedString, u64> {
        self.snapshot.dimensions.get(name).unwrap_or_else(|| {
            panic!(
                "No metric '{}' recorded per dimension '{name:?}'",
                self.name
            )
        })
    }
}
