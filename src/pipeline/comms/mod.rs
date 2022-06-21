//! Provides a way to send data to different parties of the MPC.
//!
//! Based on the [Comms] trait, implements communication via:
//!
//! * [rust channels in the same process](channel)
//!   * should only be used for testing purposes
//! * \[COMING SOON\] `gRPC`

pub mod buffer;
pub mod channel;

pub use channel::Channel;

use crate::pipeline::Result;
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Choose which helper to send data to
///
/// # Examples
///
/// ```
/// # use raw_ipa::pipeline::comms::{Channel, Comms, Target};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // this initializes all of the runtime pieces for channels
/// # let (c1, c2, c3, c_run) = raw_ipa::pipeline::util::intra_process_comms();
/// # tokio::spawn(c_run);
///
/// #[derive(serde::Serialize, serde::Deserialize)]
/// struct ExampleRequest {
///     message: String,
/// }
/// let req = ExampleRequest {
///     message: String::from("hello"),
/// };
/// c1.send_to(Target::Next, req).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum Target {
    Next,
    Prev,
}

#[async_trait]
pub trait Comms: Send + Sync + 'static {
    async fn send_to<S: Serialize + Send>(&self, target: Target, data: S) -> Result<()>;
    async fn receive_from<D: DeserializeOwned>(&self, target: Target) -> Result<D>;
    fn shared_id(&self) -> u128;
}
