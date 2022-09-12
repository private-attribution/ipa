//!
//! This module contains implementations and traits that enable MPC helpers to communicate with
//! each other. In order for helpers to send messages, they need to know the destination. In some
//! cases this might be the exact address of helper host/instance (for example IP address), but
//! in many situations MPC helpers simply need to be able to send messages to the
//! corresponding helper without needing to know the exact location - this is what this module
//! enables MPC helper service to do.
//!
use crate::helpers::error::Error;
use crate::helpers::Identity;
use crate::protocol::{RecordId, Step};
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

/// Trait for messages sent between helpers
pub trait Message: Debug + Send + Serialize + DeserializeOwned + 'static {}

impl<T> Message for T where T: Debug + Send + Serialize + DeserializeOwned + 'static {}

/// Trait for MPC helpers to communicate with each other. Helpers can send messages and
/// receive messages from a specific helper.
#[async_trait]
pub trait Mesh {
    /// Send message to the destination. Implementations are free to choose whether it is required
    /// to wait until `dest` acknowledges message or simply put it to a outgoing queue
    async fn send<T: Message>(
        &mut self,
        dest: Identity,
        record: RecordId,
        msg: T,
    ) -> Result<(), Error>;

    /// Receive a message that is associated with the given record id.
    async fn receive<T: Message>(&mut self, source: Identity, record: RecordId)
        -> Result<T, Error>;

    /// Returns the unique identity of this helper.
    fn identity(&self) -> Identity;
}

/// This is the entry point for protocols to request communication when they require it.
pub trait Gateway<M: Mesh, S: Step> {
    /// Create or return an existing channel for a given step. Protocols can send messages to
    /// any helper through this channel (see `Mesh` interface for details).
    ///
    /// This method makes no guarantee that the communication channel will actually be established
    /// between this helper and every other one. The actual connection may be created only when
    /// `Mesh::send` or `Mesh::receive` methods are called.
    fn get_channel(&self, step: S) -> M;
}
