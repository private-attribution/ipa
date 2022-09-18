use std::collections::hash_map::Iter;
use std::collections::HashMap;
use std::io::Write;

use comfy_table::Table;
use metrics::{KeyName, SharedString};

use metrics_util::debugging::{DebugValue, Snapshot};
use metrics_util::{CompositeKey, MetricKind};

/// Simple counter stats
#[derive(Debug, Default)]
pub struct CounterDetails {
    total_value: u64,
    dimensions: HashMap<SharedString, HashMap<SharedString, u64>>,
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
    counters: HashMap<KeyName, CounterDetails>,
    metric_description: HashMap<KeyName, &'static str>,
}

impl CounterDetails {
    pub fn add(&mut self, key: &CompositeKey, val: &DebugValue) {
        let val = match val {
            DebugValue::Counter(v) => v,
            _ => unreachable!(),
        };
        for label in key.key().labels() {
            let (label_key, label_val) = label.clone().into_parts();
            let dimension_values = self
                .dimensions
                .entry(label_key)
                .or_insert_with(HashMap::new);

            *dimension_values.entry(label_val).or_insert(0) += val;
        }

        self.total_value += val;
    }

    #[must_use]
    pub fn iter(&self) -> Iter<'_, SharedString, HashMap<SharedString, u64>> {
        self.dimensions.iter()
    }
}

impl Metrics {
    #[must_use]
    pub fn from_snapshot(snapshot: Snapshot) -> Self {
        let mut this = Metrics {
            counters: HashMap::new(),
            metric_description: HashMap::new(),
        };

        let snapshot = snapshot.into_vec();
        for (ckey, _, descr, val) in snapshot {
            let (key_name, _) = ckey.key().clone().into_parts();
            let entry = this
                .counters
                .entry(key_name.clone())
                .or_insert_with(CounterDetails::default);

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

    /// Dumps the stats to the provided Write interface.
    ///
    /// ## Errors
    /// returns an IO error if it fails to write to the provided writer.
    pub fn print(&self, w: &mut impl Write) -> Result<(), std::io::Error> {
        let mut metrics_table = Table::new();
        metrics_table.set_header(vec!["metric", "description", "value", "dimensions"]);

        for (key_name, counter_stats) in &self.counters {
            let mut dim_cell_content = String::new();
            for (dim, values) in counter_stats.iter() {
                dim_cell_content += format!("{dim}\n").as_str();
                for (dim_value, &counter_val) in values {
                    dim_cell_content += format!("{dim_value} = {counter_val}\n").as_str();
                }
            }

            metrics_table.add_row(vec![
                key_name.as_str(),
                self.metric_description.get(key_name).unwrap_or(&""),
                counter_stats.total_value.to_string().as_str(),
                dim_cell_content.as_str(),
            ]);
        }

        writeln!(w, "{metrics_table}")?;

        Ok(())
    }
}
