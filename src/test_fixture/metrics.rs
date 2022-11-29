use crate::telemetry::metrics::{INDEXED_PRSS_GENERATED, RECORDS_SENT, SEQUENTIAL_PRSS_GENERATED};
use metrics_runtime::data::Snapshot;
use metrics_runtime::Measurement;
use std::collections::{BTreeMap, HashMap};

/// TODO: this function is horrible and I want to fix it
pub fn print_metrics(snapshot: Snapshot) {
    let snapshot = snapshot.into_measurements();
    let mut metrics_table = BTreeMap::<_, HashMap<&'static str, u64>>::new();
    for (key, measurement) in snapshot {
        let Measurement::Counter(metric_value) = measurement else {
            continue
        };
        let key_name = key.name();

        if let Some((k, v)) = if key_name.contains(RECORDS_SENT) {
            Some((RECORDS_SENT, metric_value))
        } else if key_name.contains(INDEXED_PRSS_GENERATED) {
            Some((INDEXED_PRSS_GENERATED, metric_value))
        } else if key_name.contains(SEQUENTIAL_PRSS_GENERATED) {
            Some((SEQUENTIAL_PRSS_GENERATED, metric_value))
        } else {
            None
        } {
            let stripped_key = key_name
                .strip_suffix(k)
                .and_then(|v| v.strip_suffix('.'))
                .unwrap()
                .to_string();

            if let Some(table) = metrics_table.get_mut(&stripped_key) {
                table.insert(k, v);
            } else {
                metrics_table.entry(stripped_key).or_default().insert(k, v);
            }
        }
    }

    tracing::trace!("Helper.Step,Records sent,Indexed PRSS,Sequential PRSS");
    for (key, metrics) in metrics_table {
        tracing::trace!(
            "{},{},{},{}",
            key,
            metrics.get(RECORDS_SENT).unwrap_or(&0),
            metrics.get(INDEXED_PRSS_GENERATED).unwrap_or(&0),
            metrics.get(SEQUENTIAL_PRSS_GENERATED).unwrap_or(&0)
        );
    }
}
