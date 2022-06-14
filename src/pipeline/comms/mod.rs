//! Provides a way to send data to different parties of the MPC.
//!
//! Based on the [Comms] trait, implements communication via:
//!
//! * [rust channels in the same process](channel)
//!   * should only be used for testing purposes
//! * \[COMING SOON\] `gRPC`

pub mod channel;
pub use channel::Channel;

use crate::pipeline::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;
use uuid::Uuid;

/// Choose which helper to send data to
///
/// # Examples
///
/// ```
/// # use raw_ipa::pipeline::comms::{Channel, Comms, Target};
/// # use raw_ipa::proto;
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // this initializes all of the runtime pieces for channels
/// # let (c1, c2, c3, c_run) = raw_ipa::pipeline::util::intra_process_comms();
/// # tokio::spawn(c_run);
///
/// let message = String::from("hello");
/// c1.send_to(Target::Next, proto::pipe::ExampleRequest { message }).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub enum Target {
    Next,
    Prev,
}

#[async_trait]
pub trait Comms: Send + Sync + 'static {
    async fn send_to<M: prost::Message>(&self, target: Target, data: M) -> Result<()>;
    async fn receive_from<M: prost::Message + Default>(&self) -> Result<M>;
    async fn receive_data(&self, mut recv_chan: mpsc::Receiver<Vec<u8>>);
    fn shared_id(&self) -> Uuid;
}
