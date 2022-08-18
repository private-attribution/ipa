//! This module contains implementations and traits that enable MPC helpers to communicate with
//! each other. In order for helpers to send messages, they need to know the destination. In some
//! cases this might be the exact address of helper host/instance (for example IP address), but
//! in many situations MPC helpers orchestrated into a "ring" - every helper instance has a peer
//! on the right side and on the left side. They simply need to be able to send messages to the
//! corresponding helper without needing to know the exact location - this is what this module
//! enables MPC helper service to do.

pub mod http;
pub mod mock;

use crate::helpers::error::Error;
use crate::helpers::Identity;
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

/// Trait for messages sent between helpers
pub trait Message: Debug + Send + Serialize + DeserializeOwned + 'static {}

impl<T> Message for T where T: Debug + Send + Serialize + DeserializeOwned + 'static {}

/// Destination. Currently we only support Left and Right, but we could support the exact address
/// too
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum HelperAddr {
    Left,
    Right,
}

/// Trait for MPC helpers to communicate with each other. Helpers can send messages and
/// receive messages from a specific helper.
#[async_trait]
pub trait Ring {
    /// Send message to the destination. Implementations are free to choose whether it is required
    /// to wait until `dest` acknowledges message or simply put it to a outgoing queue
    async fn send<T: Message>(&self, dest: HelperAddr, msg: T) -> Result<(), Error>;
    async fn receive<T: Message>(&self, source: HelperAddr) -> Result<T, Error>;

    /// Returns the unique identity of this helper.
    fn identity(&self) -> Identity;
}
