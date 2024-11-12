use std::borrow::Cow;
use prometheus::{self, Encoder, TextEncoder};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry::KeyValue;
use opentelemetry::metrics::MeterProvider;

pub trait MetricsExporter {
    fn export (&self) -> Result<Vec<u8>, String>;
}

pub struct PrometheusMetricsExporter {
    scope: Cow<'static, str>,
    registry: prometheus::Registry,
    meter_provider: SdkMeterProvider,
}

impl PrometheusMetricsExporter {
    fn new(scope: impl Into<Cow<'static, str>>) -> PrometheusMetricsExporter {
        // create a new prometheus registry
        let registry = prometheus::Registry::new();

        // configure OpenTelemetry to use this registry
        let exporter = opentelemetry_prometheus::exporter()
            .with_registry(registry.clone())
            .build().unwrap();

        // set up a meter to create instruments
        let meter_provider = SdkMeterProvider::builder().with_reader(exporter).build();

        PrometheusMetricsExporter {
            scope: scope.into(),
            registry,
            meter_provider,
        }
    }
}

impl MetricsExporter for PrometheusMetricsExporter {
    fn export(&self) -> Result<Vec<u8>, String> {
        // Get snapshot from controller : how?
        // Convert the snapshot to otel struct

        let meter = self.meter_provider.meter(self.scope.clone());
        // This is basically a dummy metrics
        let counter = meter
            .u64_counter("a.counter")
            .with_description("Counts things")
            .init();
        let histogram = meter
            .u64_histogram("a.histogram")
            .with_description("Records values")
            .init();

        counter.add(100, &[KeyValue::new("key", "value")]);
        histogram.record(100, &[KeyValue::new("key", "value")]);

        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        match encoder.encode(&metric_families, &mut buffer) {
            Ok(()) => Ok(buffer),
            Err(e) => Err(format!("Failed to encode Prometheus metric: {e:?}")),
        }
    }
}