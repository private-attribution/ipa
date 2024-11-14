use axum::{routing::get, Router};
use hyper::StatusCode;
use opentelemetry::KeyValue;

use crate::net::{
    http_serde::{self},
    Error,
};

use opentelemetry::metrics::MeterProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::{self, Encoder, TextEncoder};

/// Takes details from the HTTP request and creates a `[TransportCommand]::CreateQuery` that is sent
/// to the [`HttpTransport`].
async fn handler(// transport: Extension<MpcHttpTransport>,
    // QueryConfigQueryParams(query_config): QueryConfigQueryParams,
) -> Result<Vec<u8>, Error> {
    // match transport.dispatch(query_config, BodyStream::empty()).await {
    //     Ok(resp) => Ok(Json(resp.try_into()?)),
    //     Err(err @ ApiError::NewQuery(NewQueryError::State { .. })) => {
    //         Err(Error::application(StatusCode::CONFLICT, err))
    //     }
    //     Err(err) => Err(Error::application(StatusCode::INTERNAL_SERVER_ERROR, err)),
    // }

    // TODO: Remove this dummy metrics and get metrics for scraper from ipa-metrics::PrometheusMetricsExporter (see ipa-metrics/exporter.rs)

    // create a new prometheus registry
    let registry = prometheus::Registry::new();

    // configure OpenTelemetry to use this registry
    let exporter = opentelemetry_prometheus::exporter()
        .with_registry(registry.clone())
        .build()
        .unwrap();

    // set up a meter to create instruments
    let provider = SdkMeterProvider::builder().with_reader(exporter).build();
    let meter = provider.meter("ipa-helper");

    // Use two instruments
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

    // Encode data as text or protobuf
    let encoder = TextEncoder::new();
    let metric_families = registry.gather();
    let mut result = Vec::new();
    match encoder.encode(&metric_families, &mut result) {
        Ok(()) => Ok(result),
        Err(err) => Err(Error::application(StatusCode::INTERNAL_SERVER_ERROR, err)),
    }
}

pub fn router() -> Router {
    Router::new().route(http_serde::metrics::AXUM_PATH, get(handler))
}
