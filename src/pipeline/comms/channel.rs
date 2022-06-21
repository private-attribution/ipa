//! Implementation of [Comms] for channels within the same process.
//!
//! Mostly for use in testing and prototyping on the same machine. Since there is no network
//! activity, should not be used for any kind of performance testing.
//!
//! # Examples
//!
//! ```
//! # use raw_ipa::pipeline::comms::{Channel, Comms, Target};
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // helper function that sets up 3 helpers hooked up to each other with channels
//! let (c1, c2, c3, c_run) = raw_ipa::pipeline::util::intra_process_comms();
//! tokio::spawn(c_run); // this initializes all of the runtime pieces for channels
//!
//! #[derive(Clone, serde::Serialize, serde::Deserialize)]
//! struct ExampleRequest {
//!     message: String,
//! }
//! let req = ExampleRequest {
//!     message: String::from("hello"),
//! };
//! c1.send_to(Target::Next, req.clone()).await?;
//! let recvd = c2.receive_from::<ExampleRequest>(Target::Prev).await?;
//! assert_eq!(req.message, recvd.message);
//! # Ok(())
//! # }
//! ```

use crate::pipeline::comms::buffer::{self, as_source};
use crate::pipeline::comms::{Comms, Target};
use crate::pipeline::Result;
use async_trait::async_trait;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;

pub struct Channel<B: buffer::Buffer> {
    name: &'static str,
    next_send_chan: mpsc::Sender<Vec<u8>>,
    prev_send_chan: mpsc::Sender<Vec<u8>>,
    buffer: B,
    shared_id: u128,
}
impl<B: buffer::Buffer> Channel<B> {
    #[must_use]
    pub fn new(
        name: &'static str,
        next_send_chan: mpsc::Sender<Vec<u8>>,
        prev_send_chan: mpsc::Sender<Vec<u8>>,
        buffer: B,
        shared_id: u128,
    ) -> Channel<B> {
        Channel {
            name,
            next_send_chan,
            prev_send_chan,
            buffer,
            shared_id,
        }
    }

    pub async fn receive_data(&self, mut recv_chan: mpsc::Receiver<Vec<u8>>) {
        while let Some(data) = recv_chan.recv().await {
            let chan_mess_res: Result<ChannelMessage> =
                serde_json::from_slice(data.as_slice()).map_err(Into::into);
            match chan_mess_res {
                Err(err) => error!("received unexpected message: {}", err),
                Ok(chan_mess) => {
                    let sent = self
                        .buffer
                        .write(chan_mess.shared_id, chan_mess.source, chan_mess.data)
                        .await;
                    if sent.is_err() {
                        error!("could not send message to buffer: {}", sent.unwrap_err());
                        continue;
                    }
                }
            }
        }
    }
}

impl<B: buffer::Buffer> Drop for Channel<B> {
    fn drop(&mut self) {
        info!("{} comms closing", self.name);
    }
}

#[derive(Serialize, Deserialize)]
struct ChannelMessage {
    shared_id: u128,
    source: Target,
    data: Vec<u8>,
}

#[async_trait]
impl<B: buffer::Buffer + 'static> Comms for Channel<B> {
    async fn send_to<S: serde::Serialize + Send>(&self, target: Target, data: S) -> Result<()> {
        let chan = match target {
            Target::Next => &self.next_send_chan,
            Target::Prev => &self.prev_send_chan,
        };

        let data_se = serde_json::to_vec(&data)?;
        let chan_message = ChannelMessage {
            shared_id: self.shared_id,
            source: as_source(&target),
            data: data_se,
        };
        let b = serde_json::to_vec(&chan_message)?;

        chan.send(b).await?;
        Ok(())
    }

    async fn receive_from<D: serde::de::DeserializeOwned>(&self, source: Target) -> Result<D> {
        // basic poll for now; will use watchers in real implementation
        loop {
            match self
                .buffer
                .get_and_remove(self.shared_id, source.clone())
                .await
            {
                Err(err) => return Err(err),
                Ok(None) => {
                    debug!("nothing in cache, {} waiting...", self.name);
                    time::sleep(Duration::from_millis(500)).await;
                }
                Ok(Some(v)) => {
                    let res: D = serde_json::from_reader(std::io::Cursor::new(v))?;
                    debug!("{} received data", self.name);
                    return Ok(res);
                }
            }
        }
    }

    #[inline]
    fn shared_id(&self) -> u128 {
        self.shared_id
    }
}
