use crossbeam_channel::Sender;

use crate::{context::CurrentThreadContext, MetricsStore};

#[derive(Clone)]
pub struct Producer {
    pub(super) tx: Sender<MetricsStore>,
}

impl Producer {
    pub fn install(&self) {
        CurrentThreadContext::init(self.tx.clone());
    }

    /// Returns a drop handle that should be used when thread is stopped.
    /// In an ideal world, a destructor on [`MetricsContext`] could do this,
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
        CurrentThreadContext::flush()
    }
}
