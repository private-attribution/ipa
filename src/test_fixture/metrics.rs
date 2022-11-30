use crate::telemetry::metrics::{INDEXED_PRSS_GENERATED, RECORDS_SENT, SEQUENTIAL_PRSS_GENERATED};
use metrics_runtime::data::Snapshot;
use metrics_runtime::Measurement;
use std::collections::{BTreeSet, HashMap};

/// Represent metrics collected from running MPC circuit. For test environment it will have metrics
/// collected from all 3 running processes. Supports counters only at the moment
struct MetricStats {
    counters: HashMap<String, HashMap<String, u64>>,
    /// Scope is a unique string that captures the environment for the collected metrics. For example
    /// scope can be composed of helper role, current step etc.
    scopes: BTreeSet<String>,
}

impl MetricStats {
    pub fn new(snapshot: Snapshot) -> Self {
        let mut counters: HashMap<String, HashMap<String, u64>> = HashMap::new();
        let mut scopes = BTreeSet::new();
        for (key, measurement) in snapshot.into_measurements() {
            let Measurement::Counter(val) = measurement else {
                tracing::warn!("{key:?} is not a supported measurement. Only counters are supported");
                continue
            };

            let key = key.name();
            let (scope, metric_name) = key.rsplit_once('.').unwrap();
            *counters
                .entry(metric_name.to_string())
                .or_default()
                .entry(scope.to_string())
                .or_default() += val;
            scopes.insert(scope.to_string());
        }

        Self { counters, scopes }
    }

    pub fn all_scopes(&self) -> impl Iterator<Item = &str> {
        self.scopes.iter().map(AsRef::as_ref)
    }

    pub fn scope<'a>(&'a self, scope_name: &'a str) -> StatsScope<'a> {
        StatsScope::new(self, scope_name)
    }
}

struct StatsScope<'a> {
    stats: &'a MetricStats,
    fixed_scope: &'a str,
}

impl<'a> StatsScope<'a> {
    pub fn new(stats: &'a MetricStats, fixed_scope: &'a str) -> Self {
        Self { stats, fixed_scope }
    }

    pub fn get_counter(&self, name: &str) -> Option<u64> {
        self.stats
            .counters
            .get(name)
            .and_then(|scopes| scopes.get(self.fixed_scope).copied())
    }
}

/// TODO: make a trait to collect tables to csv, json, etc and make function generic over it
pub fn print_metrics(snapshot: Snapshot) {
    let metrics = MetricStats::new(snapshot);

    tracing::trace!("Helper.Step,Records sent,Indexed PRSS,Sequential PRSS");
    for scope_name in metrics.all_scopes() {
        let scope = metrics.scope(scope_name);
        tracing::trace!(
            "{},{},{},{}",
            scope_name,
            scope.get_counter(RECORDS_SENT).unwrap_or(0),
            scope.get_counter(INDEXED_PRSS_GENERATED).unwrap_or(0),
            scope.get_counter(SEQUENTIAL_PRSS_GENERATED).unwrap_or(0)
        );
    }
}
