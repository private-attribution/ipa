use std::io;

use ipa_metrics::MetricsStore;
use opentelemetry::{metrics::MeterProvider, KeyValue};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::{self, Encoder, TextEncoder};

pub trait PrometheusMetricsExporter {
    fn export<W: io::Write>(&mut self, w: &mut W);
}

impl PrometheusMetricsExporter for MetricsStore {
    fn export<W: io::Write>(&mut self, w: &mut W) {
        // Setup prometheus registry and open-telemetry exporter
        let registry = prometheus::Registry::new();

        let exporter = opentelemetry_prometheus::exporter()
            .with_registry(registry.clone())
            .build()
            .unwrap();

        let meter_provider = SdkMeterProvider::builder().with_reader(exporter).build();

        // Convert the snapshot to otel struct
        // TODO : We need to define a proper scope for the metrics
        let meter = meter_provider.meter("ipa-helper");

        let counters = self.counters();
        counters.for_each(|(counter_name, counter_value)| {
            let otlp_counter = meter.u64_counter(counter_name.key).init();

            let attributes: Vec<KeyValue> = counter_name
                .labels()
                .map(|l| KeyValue::new(l.name, l.val.to_string()))
                .collect();

            otlp_counter.add(counter_value, &attributes[..]);
        });

        let encoder = TextEncoder::new();
        let metric_families = registry.gather();
        encoder.encode(&metric_families, w).unwrap();
    }
}

#[cfg(test)]
mod test {

    use std::thread;

    use ipa_metrics::{counter, install_new_thread, MetricChannelType};

    use super::PrometheusMetricsExporter;

    #[test]
    fn export_to_prometheus() {
        let (producer, controller, _) = install_new_thread(MetricChannelType::Rendezvous).unwrap();

        thread::spawn(move || {
            producer.install();
            counter!("baz", 4);
            counter!("bar", 1);
            let _ = producer.drop_handle();
        })
        .join()
        .unwrap();

        let mut store = controller.snapshot().unwrap();

        let mut buff = Vec::new();
        store.export(&mut buff);

        let expected_result = "# TYPE bar_total counter
bar_total{otel_scope_name=\"ipa-helper\"} 1
# TYPE baz_total counter
baz_total{otel_scope_name=\"ipa-helper\"} 4
# HELP target_info Target metadata
# TYPE target_info gauge
target_info{service_name=\"unknown_service\",telemetry_sdk_language=\"rust\",telemetry_sdk_name=\"opentelemetry\",telemetry_sdk_version=\"0.24.1\"} 1\n";
        let result = String::from_utf8(buff).unwrap();
        assert_eq!(result, expected_result);
    }
}
