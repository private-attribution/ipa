//! [`Buffer`] describes the functionality needed to have a distributed read/write buffer between the
//! network layer and compute layer. It is needed because running pipelines send data to other
//! running pipelines asynchronously, and so there must be a way to await the data until the
//! receiving pipeline is ready. This provides a storage layer for that data to wait in.
//!
//! As of now, the only implementation is [`Mem`], which is an in-memory hashmap. While other
//! implementations are possible, it's likely that the latency associated with a file read/write
//! would be too large to associate with every piece of data sent.
//!
//! See [`mem`] for an example usage of [`Buffer`].

pub mod mem;

pub use mem::Mem;

use crate::pipeline::comms::Target;
use crate::pipeline::Result;
use async_trait::async_trait;
use tokio::sync::oneshot;

#[async_trait]
pub trait Buffer: Send + Sync {
    async fn write(&self, key: u128, source: Target, value: Vec<u8>) -> Result<()>;
    async fn get_and_remove(&self, key: u128, source: Target) -> Result<Option<Vec<u8>>>;
}

#[derive(Debug)]
enum Command {
    Write(u128, Target, Vec<u8>),
    /// Removes and returns the value in the oneshot receiver
    GetAndRemove(u128, Target, oneshot::Sender<Option<Vec<u8>>>),
}

/// When sending data to a different helper, the receiving helper should know which helper sent the
/// data. This function determines which helper is acting as the source of the data.
pub(super) fn as_source(target: &Target) -> Target {
    match target {
        Target::Next => Target::Prev, // if sending data to next helper, acting as the prev helper
        Target::Prev => Target::Next, // if sending data to prev helper, acting as the next helper
    }
}
