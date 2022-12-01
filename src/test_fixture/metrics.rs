use metrics_tracing_context::TracingContextLayer;
use metrics_util::debugging::{DebuggingRecorder, Snapshot, Snapshotter};
use metrics_util::layers::Layer;
use once_cell::sync::OnceCell;


// TODO: move to OnceCell from std once it is stabilized
static ONCE: OnceCell<Snapshotter> = OnceCell::new();

pub fn setup() {
    ONCE.get_or_init(|| {
        if metrics::try_recorder().is_some() {
            panic!("metric recorder has already been installed");
        }

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let recorder = Box::leak(Box::new(TracingContextLayer::all().layer(recorder)));
        metrics::set_recorder(recorder).unwrap();

        snapshotter
    });
}

pub fn snapshot() -> Snapshot {
    ONCE.get().unwrap().snapshot()
}