use metrics_util::debugging::{DebuggingRecorder, Snapshot};
use once_cell::sync::OnceCell;


// TODO: move to OnceCell from std once it is stabilized
static ONCE: OnceCell<&'static DebuggingRecorder> = OnceCell::new();

pub(super) fn setup() {
    ONCE.get_or_init(|| {
            if metrics::try_recorder().is_some() {
                panic!("metric recorder has already been installed");
            }

            let recorder = Box::leak(Box::new(DebuggingRecorder::new()));
            metrics::set_recorder(recorder).unwrap();

            recorder
    });
}

pub(super) fn snapshot() -> Snapshot {
    ONCE.get().unwrap().snapshotter().snapshot()
}