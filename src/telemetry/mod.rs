pub mod metrics {
    use metrics::describe_counter;
    use metrics::Unit;

    pub const REQUESTS_RECEIVED: &str = "requests.received";

    /// Registers metrics used in the system with the metrics recorder.
    ///
    /// ## Panics
    /// Panic if there is no recorder installed
    pub fn register() {
        assert!(
            matches!(metrics::try_recorder(), Some(_)),
            "metrics recorder must be installed before metrics can be described"
        );

        describe_counter!(
            REQUESTS_RECEIVED,
            Unit::Count,
            "Total number of requests received by the web server"
        );
    }

    #[cfg(test)]
    #[must_use]
    pub fn get_counter_value(
        snapshot: metrics_util::debugging::Snapshot,
        metric_name: &'static str,
    ) -> Option<u64> {
        use metrics_util::debugging::DebugValue;
        use metrics_util::MetricKind;

        let snapshot = snapshot.into_vec();

        for (key, _unit, _, val) in snapshot {
            if key.kind() == MetricKind::Counter
                && key.key().name().eq_ignore_ascii_case(metric_name)
            {
                match val {
                    DebugValue::Counter(v) => return Some(v),
                    _ => unreachable!(),
                }
            }
        }

        None
    }
}
