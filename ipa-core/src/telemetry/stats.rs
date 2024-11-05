use std::{
    collections::{
        hash_map::{Entry, Iter},
        HashMap,
    },
    fmt::Display,
};

use ipa_metrics::{MetricPartition, MetricsStore};

use crate::{helpers::Role, protocol::Gate, telemetry::labels};

/// Simple counter stats
#[derive(Debug, Default)]
pub struct CounterDetails {
    pub total_value: u64,
    pub dimensions: HashMap<&'static str, HashMap<String, u64>>,
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
#[derive(Default)]
pub struct Metrics {
    pub counters: HashMap<&'static str, CounterDetails>,
}

pub struct CompositeKey {
    pub key: &'static str,
    pub labels: Vec<Label>,
}

#[derive(Clone)]
pub struct Label {
    pub name: &'static str,
    pub value: String,
}

impl CounterDetails {
    pub fn add(&mut self, key: &CompositeKey, val: u64) {
        for label in &key.labels {
            let Label { name, value } = label.clone();
            let dimension_values = self.dimensions.entry(name).or_default();

            *dimension_values.entry(value).or_insert(0) += val;
        }

        self.total_value += val;
    }

    #[must_use]
    pub fn iter(&self) -> Iter<'_, &'static str, HashMap<String, u64>> {
        self.dimensions.iter()
    }
}

impl<'a> IntoIterator for &'a CounterDetails {
    type Item = <Self::IntoIter as Iterator>::Item;
    type IntoIter = Iter<'a, &'static str, HashMap<String, u64>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Display for Metrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        if self.counters.is_empty() {
            return Ok(());
        }

        let mut metrics_table = comfy_table::Table::new();
        metrics_table.set_header(vec!["metric", "value", "dimensions"]);

        for (key_name, counter_stats) in &self.counters {
            let mut dim_cell_content = String::new();
            for (dim, values) in counter_stats {
                dim_cell_content += format!("{dim}\n").as_str();
                for (dim_value, &counter_val) in values {
                    dim_cell_content += format!("{dim_value} = {counter_val}\n").as_str();
                }
            }

            metrics_table.add_row(vec![
                key_name,
                counter_stats.total_value.to_string().as_str(),
                dim_cell_content.as_str(),
            ]);
        }

        metrics_table.fmt(f)
    }
}

impl Metrics {
    /// Builds a new metric snapshot for the specified partition.
    ///
    /// ## Panics
    /// If partition does not exist in the metrics store.
    #[must_use]
    pub fn from_partition(metrics_store: &MetricsStore, partition: MetricPartition) -> Self {
        let v = metrics_store.with_partition(partition, |store| {
            let mut this = Self::default();
            for (counter, value) in store.counters() {
                let composite_key = CompositeKey {
                    key: counter.key,
                    labels: counter
                        .labels()
                        .map(|l| Label {
                            name: l.name,
                            value: l.val.to_string(),
                        })
                        .collect::<Vec<_>>(),
                };
                match this.counters.entry(composite_key.key) {
                    Entry::Occupied(mut entry) => entry.get_mut().add(&composite_key, value),
                    Entry::Vacant(entry) => {
                        let mut counter_details = CounterDetails::default();
                        counter_details.add(&composite_key, value);
                        entry.insert(counter_details);
                    }
                }
            }

            this
        });

        v.unwrap_or_else(|| panic!("Partition {partition} does not exist"))
    }

    #[must_use]
    pub fn get_counter(&self, name: &'static str) -> u64 {
        self.counters
            .get(name)
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
            .get(name)
            .unwrap_or_else(|| panic!("{name} metric does not exist in the snapshot"));
        MetricAssertion {
            name,
            snapshot: details,
        }
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

    fn get_dimension(&self, name: &'static str) -> &HashMap<String, u64> {
        self.snapshot.dimensions.get(name).unwrap_or_else(|| {
            panic!(
                "No metric '{}' recorded per dimension '{name:?}'",
                self.name
            )
        })
    }
}
