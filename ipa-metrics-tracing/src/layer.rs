use std::fmt::Debug;
use tracing::{Id, Instrument, Subscriber};
use tracing::field::{Field, Visit};
use tracing::instrument::WithSubscriber;
use tracing::span::{Attributes, Record};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

/// This layer allows partitioning metric stores.
/// This can be used in tests, where each unit test
/// creates its own unique root span. Upon entering
/// this span, this layer sets a unique partition key
struct MetricsPartitioningLayer;


#[derive(Default)]
struct MaybeMetricPartition(Option<u128>);

impl Visit for MaybeMetricPartition {
    fn record_u128(&mut self, field: &Field, value: u128) {
        if field.name() == "metric-partition" {
            self.0 = Some(value);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        // not interested in anything else except u128 values.
    }
}

struct MetricPartition(u128);


impl <S: Subscriber + for <'s> LookupSpan<'s>> Layer<S> for MetricsPartitioningLayer {
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let record = Record::new(attrs.values());
        let mut metric_partition = MaybeMetricPartition::default();
        record.record(&mut metric_partition);
        if let Some(v) = metric_partition.0 {
            let span = ctx.span(id).expect("Span should exists upon entering");
            span.extensions_mut().insert(MetricPartition(v));
        }

    }


    fn on_enter(&self, id: &Id, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("Span should exists upon entering");
        if let Some(MetricPartition(v)) = span.extensions().get::<MetricPartition>() {

        };
    }

    fn on_exit(&self, _id: &Id, _ctx: Context<'_, S>) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn basic() {

    }
}