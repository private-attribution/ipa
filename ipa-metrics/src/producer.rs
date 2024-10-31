use crossbeam_channel::Sender;

use crate::{context::CurrentThreadContext, MetricsStore};

/// A handle to enable centralized metrics collection from the current thread.
///
/// This is a cloneable handle, so it can be installed in multiple threads.
/// The handle is installed by calling [`install`], which returns a drop handle.
/// When the drop handle is dropped, the context of local store is flushed
/// to the collector thread.
///
/// Thread local store is always enabled by [`MetricsContext`], so it is always
/// possible to have a local view of metrics emitted by this thread.
///
/// [`install`]: Producer::install
#[derive(Clone)]
pub struct Producer {
    pub(super) tx: Sender<MetricsStore>,
}

impl Producer {
    pub fn install(&self) {
        CurrentThreadContext::init(self.tx.clone());
    }

    /// Returns a drop handle that should be used when thread is stopped.
    /// One may think destructor on [`MetricsContext`] could do this,
    /// but as pointed in [`LocalKey`] documentation, deadlocks are possible
    /// if another TLS storage is accessed at destruction time.
    ///
    /// I actually ran into this problem with crossbeam channels. Send operation
    /// requires access to `thread::current` and that panics at runtime if called
    /// from inside `Drop`.
    ///
    /// [`LocalKey`]: <https://doc.rust-lang.org/std/thread/struct.LocalKey.html#platform-specific-behavior>
    pub fn drop_handle(&self) -> ProducerDropHandle {
        ProducerDropHandle
    }
}

#[must_use]
pub struct ProducerDropHandle;

impl Drop for ProducerDropHandle {
    fn drop(&mut self) {
        CurrentThreadContext::flush();
    }
}
