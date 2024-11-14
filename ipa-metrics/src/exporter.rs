use std::io;

use opentelemetry::metrics::{Meter, MeterProvider};
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::{self, Encoder, TextEncoder};

use crate::MetricsStore;

pub trait PrometheusMetricsExporter {
    fn export<W: io::Write>(&mut self, w: &mut W);
}

impl MetricsStore {
    fn to_otlp(&mut self, meter: &Meter) {
        let counters = self.counters();

        counters.for_each(|(counter_name, counter_value)| {
            let otlp_counter = meter.u64_counter(counter_name.key).init();

            let attributes: Vec<KeyValue> = counter_name
                .labels()
                .map(|l| KeyValue::new(l.name, l.val.to_string()))
                .collect();

            otlp_counter.add(counter_value, &attributes[..]);
        });
    }
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
        self.to_otlp(&meter);

        let encoder = TextEncoder::new();
        let metric_families = registry.gather();
        // TODO: Handle error?
        encoder.encode(&metric_families, w).unwrap();
    }
}

mod test {

    use std::thread::{self, Scope, ScopedJoinHandle};

    use super::PrometheusMetricsExporter;
    use crate::{counter, install_new_thread, producer::Producer, MetricChannelType};
    struct MeteredScope<'scope, 'env: 'scope>(&'scope Scope<'scope, 'env>, Producer);

    impl<'scope, 'env: 'scope> MeteredScope<'scope, 'env> {
        fn spawn<F, T>(&self, f: F) -> ScopedJoinHandle<'scope, T>
        where
            F: FnOnce() -> T + Send + 'scope,
            T: Send + 'scope,
        {
            let producer = self.1.clone();

            self.0.spawn(move || {
                producer.install();
                let r = f();
                let _ = producer.drop_handle();

                r
            })
        }
    }

    trait IntoMetered<'scope, 'env: 'scope> {
        fn metered(&'scope self, meter: Producer) -> MeteredScope<'scope, 'env>;
    }

    impl<'scope, 'env: 'scope> IntoMetered<'scope, 'env> for Scope<'scope, 'env> {
        fn metered(&'scope self, meter: Producer) -> MeteredScope<'scope, 'env> {
            MeteredScope(self, meter)
        }
    }

    #[test]
    fn export_to_prometheus() {
        let (producer, controller, _) = install_new_thread(MetricChannelType::Rendezvous).unwrap();

        thread::scope(move |s| {
            let s = s.metered(producer);
            s.spawn(|| counter!("baz", 4)).join().unwrap();
            s.spawn(|| counter!("bar", 1)).join().unwrap();

            let mut store = controller
                .snapshot()
                .expect("Metrics snapshot must be available");

            let mut buff = Vec::new();
            store.export(&mut buff);

            let result = String::from_utf8(buff).unwrap();
            println!("{result}");
        });
    }
}
