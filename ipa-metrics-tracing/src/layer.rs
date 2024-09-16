use std::fmt::Debug;

use tracing::{
    field::{Field, Visit},
    instrument::WithSubscriber,
    span::{Attributes, Record},
    Id, Instrument, Subscriber,
};
use tracing_subscriber::{layer::Context, registry::LookupSpan, Layer};

/// This layer allows partitioning metric stores.
/// This can be used in tests, where each unit test
/// creates its own unique root span. Upon entering
/// this span, this layer sets a unique partition key
#[derive(Default)]
pub struct MetricsPartitioningLayer;

#[derive(Default)]
struct MaybeMetricPartition(Option<u128>);

impl Visit for MaybeMetricPartition {
    fn record_u128(&mut self, field: &Field, value: u128) {
        if field.name() == "metrics-partition" {
            self.0 = Some(value);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        // not interested in anything else except u128 values.
    }
}

struct MetricPartition(Option<u128>, u128);

impl<S: Subscriber + for<'s> LookupSpan<'s>> Layer<S> for MetricsPartitioningLayer {
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let record = Record::new(attrs.values());
        let mut metric_partition = MaybeMetricPartition::default();
        record.record(&mut metric_partition);
        if let Some(v) = metric_partition.0 {
            let span = ctx.span(id).expect("Span should exists upon entering");
            span.extensions_mut().insert(MetricPartition(None, v));
        }
    }

    fn on_enter(&self, id: &Id, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("Span should exists upon entering");
        if let Some(MetricPartition(ref mut cur, v)) = span.extensions_mut().get_mut() {
            *cur = ipa_metrics::current_partition();
            eprintln!("Setting partition to {}", v);
            ipa_metrics::set_partition(*v)
        };
    }

    fn on_exit(&self, id: &Id, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("Span should exists upon entering");
        if let Some(MetricPartition(prev, _)) = span.extensions_mut().get_mut() {
            eprintln!("Unsetting partition to {:?}", prev);
            ipa_metrics::set_or_unset_partition(prev.take())
        };
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn basic() {}
}
