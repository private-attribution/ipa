use std::fmt::Debug;

use ipa_metrics::{CurrentThreadPartitionContext, MetricPartition, MetricsCurrentThreadContext};
use tracing::{
    field::{Field, Visit},
    span::{Attributes, Record},
    Id, Subscriber,
};
use tracing_subscriber::{
    layer::Context,
    registry::{Extensions, ExtensionsMut, LookupSpan},
    Layer,
};

pub const FIELD: &str = concat!(env!("CARGO_PKG_NAME"), "-", "metrics-partition");

/// This layer allows partitioning metric stores.
/// This can be used in tests, where each unit test
/// creates its own unique root span. Upon entering
/// this span, this layer sets a unique partition key
#[derive(Default)]
pub struct MetricsPartitioningLayer;

impl<S: Subscriber + for<'s> LookupSpan<'s>> Layer<S> for MetricsPartitioningLayer {
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        #[derive(Default)]
        struct MaybeMetricPartition(Option<MetricPartition>);

        impl Visit for MaybeMetricPartition {
            fn record_u64(&mut self, field: &Field, value: u64) {
                if field.name() == FIELD {
                    self.0 = Some(value);
                }
            }

            fn record_debug(&mut self, _field: &Field, _value: &dyn Debug) {
                // not interested in anything else except MetricPartition values.
            }
        }

        let record = Record::new(attrs.values());
        let mut metric_partition = MaybeMetricPartition::default();
        record.record(&mut metric_partition);
        if let Some(v) = metric_partition.0 {
            let span = ctx.span(id).expect("Span should exists upon entering");
            span.extensions_mut().insert(MetricPartitionExt {
                prev: None,
                current: v,
            });
        }
    }

    fn on_enter(&self, id: &Id, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("Span should exists upon entering");
        MetricPartitionExt::span_enter(span.extensions_mut());
    }

    fn on_exit(&self, id: &Id, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("Span should exists upon exiting");
        MetricPartitionExt::span_exit(span.extensions_mut());
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let span = ctx.span(&id).expect("Span should exists before closing it");
        MetricPartitionExt::span_close(&span.extensions());
    }
}

struct MetricPartitionExt {
    // Partition active before span is entered.
    prev: Option<MetricPartition>,
    // Partition that must be set when this span is entered.
    current: MetricPartition,
}

impl MetricPartitionExt {
    fn span_enter(mut span_ext: ExtensionsMut<'_>) {
        if let Some(MetricPartitionExt { current, prev }) = span_ext.get_mut() {
            *prev = CurrentThreadPartitionContext::get();
            CurrentThreadPartitionContext::set(*current);
        }
    }

    fn span_exit(mut span_ext: ExtensionsMut) {
        if let Some(MetricPartitionExt { prev, .. }) = span_ext.get_mut() {
            CurrentThreadPartitionContext::toggle(prev.take());
        }
    }

    fn span_close(span_ext: &Extensions) {
        if let Some(MetricPartitionExt { .. }) = span_ext.get() {
            MetricsCurrentThreadContext::flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use ipa_metrics::CurrentThreadPartitionContext;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    use crate::{layer::FIELD, MetricsPartitioningLayer};

    #[test]
    fn basic() {
        CurrentThreadPartitionContext::set(0);
        tracing_subscriber::registry()
            .with(MetricsPartitioningLayer)
            .init();
        let span1 = tracing::info_span!("", { FIELD } = 1_u64);
        let span2 = tracing::info_span!("", { FIELD } = 2_u64);
        {
            let _guard1 = span1.enter();
            assert_eq!(Some(1), CurrentThreadPartitionContext::get());
            {
                let _guard2 = span2.enter();
                assert_eq!(Some(2), CurrentThreadPartitionContext::get());
            }
            assert_eq!(Some(1), CurrentThreadPartitionContext::get());
        }
        assert_eq!(Some(0), CurrentThreadPartitionContext::get());
    }
}
