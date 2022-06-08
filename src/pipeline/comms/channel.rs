//! Implementation of [Comms] for channels within the same process.
//!
//! Mostly for use in testing and prototyping on the same machine. Since there is no network
//! activity, should not be used for any kind of performance testing.
//!
//! # Examples
//!
//! ```
//! # use raw_ipa::pipeline::comms::channel::Channel;
//! # use raw_ipa::pipeline::comms::Target;
//! # use raw_ipa::proto;
//! # use raw_ipa::pipeline::comms::Comms;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let (c1, c2, c3, c_run) = Channel::all_comms();
//! tokio::spawn(c_run); // this initializes all of the runtime pieces for channels
//!
//! let message = "hello";
//! c1.send_to(Target::Next, proto::pipe::ExampleRequest { message })?;
//! let recvd = c2.receive_from::<proto::pipe::ExampleRequest>()?;
//! assert_eq!(message, recvd.message);
//! # Ok(())
//! # }
//! ```

use crate::pipeline::comms::{Comms, Target};
use crate::pipeline::hashmap_thread::{HashMapCommand, HashMapHandler};
use crate::pipeline::Result;
use async_trait::async_trait;
use log::{debug, error, info};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::{time, try_join};
use uuid::Uuid;

pub struct Channel {
    name: &'static str,
    next_send_chan: mpsc::Sender<Vec<u8>>,
    prev_send_chan: mpsc::Sender<Vec<u8>>,
    hashmap_send: mpsc::Sender<HashMapCommand>,
    shared_id: Uuid,
}
impl Channel {
    #[must_use]
    pub fn new(
        name: &'static str,
        next_send_chan: mpsc::Sender<Vec<u8>>,
        prev_send_chan: mpsc::Sender<Vec<u8>>,
        hashmap_send: mpsc::Sender<HashMapCommand>,
        shared_id: Uuid,
    ) -> Channel {
        Channel {
            name,
            next_send_chan,
            prev_send_chan,
            hashmap_send,
            shared_id,
        }
    }

    pub fn all_comms() -> (
        Arc<Channel>,
        Arc<Channel>,
        Arc<Channel>,
        impl Future<Output = Result<()>>,
    ) {
        let shared_id = Uuid::new_v4();
        let (h1_send, h1_recv) = mpsc::channel(32);
        let (h2_send, h2_recv) = mpsc::channel(32);
        let (h3_send, h3_recv) = mpsc::channel(32);

        let (h1_hashmap_send, h1_hashmap_recv) = mpsc::channel(32);
        let (h2_hashmap_send, h2_hashmap_recv) = mpsc::channel(32);
        let (h3_hashmap_send, h3_hashmap_recv) = mpsc::channel(32);
        let h1_hashmap = HashMapHandler::new("hm1", h1_hashmap_recv);
        let h2_hashmap = HashMapHandler::new("hm2", h2_hashmap_recv);
        let h3_hashmap = HashMapHandler::new("hm3", h3_hashmap_recv);

        let h1 = Arc::new(Channel::new(
            "helper_1",
            h2_send.clone(),
            h3_send.clone(),
            h1_hashmap_send,
            shared_id,
        ));
        let h2 = Arc::new(Channel::new(
            "helper_2",
            h3_send,
            h1_send.clone(),
            h2_hashmap_send,
            shared_id,
        ));
        let h3 = Arc::new(Channel::new(
            "helper_3",
            h1_send,
            h2_send,
            h3_hashmap_send,
            shared_id,
        ));

        let run = {
            let chan1 = h1.clone();
            let chan2 = h2.clone();
            let chan3 = h3.clone();
            async move {
                try_join!(
                    tokio::spawn(async move { chan1.receive_data(h1_recv).await }),
                    tokio::spawn(async move { chan2.receive_data(h2_recv).await }),
                    tokio::spawn(async move { chan3.receive_data(h3_recv).await }),
                    tokio::spawn(async move { h1_hashmap.run().await }),
                    tokio::spawn(async move { h2_hashmap.run().await }),
                    tokio::spawn(async move { h3_hashmap.run().await }),
                )?;
                Ok(())
            }
        };
        (h1, h2, h3, run)
    }

    pub async fn receive_data(&self, mut recv_chan: mpsc::Receiver<Vec<u8>>) {
        while let Some(data) = recv_chan.recv().await {
            let chan_mess_res: Result<ChannelMessage> =
                serde_json::from_slice(data.as_slice()).map_err(Into::into);
            match chan_mess_res {
                Err(err) => error!("received unexpected message: {}", err),
                Ok(chan_mess) => {
                    let sent = self
                        .hashmap_send
                        .send(HashMapCommand::Write(chan_mess.shared_id, chan_mess.buf))
                        .await;
                    if sent.is_err() {
                        error!("could not send message to hashmap: {}", sent.unwrap_err());
                        continue;
                    }
                }
            }
        }
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        info!("{} comms closing", self.name);
    }
}

#[derive(Serialize, Deserialize)]
struct ChannelMessage {
    shared_id: Uuid,
    buf: Vec<u8>,
}

#[async_trait]
impl Comms for Channel {
    async fn send_to<M: Message>(&self, target: Target, data: M) -> Result<()> {
        let mut buf = Vec::with_capacity(data.encoded_len());
        // unwrap is safe because `buf` has `encoded_len` reserved
        data.encode(&mut buf).unwrap();
        let chan_message = ChannelMessage {
            shared_id: self.shared_id(),
            buf,
        };
        let res = serde_json::to_vec(&chan_message)?;
        let chan = match target {
            Target::Next => &self.next_send_chan,
            Target::Prev => &self.prev_send_chan,
        };
        chan.send(res).await?;
        Ok(())
    }

    async fn receive_from<M: Message + Default>(&self) -> Result<M> {
        // basic poll for now; will use watchers in real implementation
        loop {
            let (tx, rx) = oneshot::channel();
            self.hashmap_send
                .send(HashMapCommand::Remove(self.shared_id(), tx))
                .await?;
            match rx.await {
                Err(err) => return Err(err.into()),
                Ok(None) => {
                    debug!("nothing in cache, {} waiting...", self.name);
                    time::sleep(Duration::from_millis(500)).await;
                }
                Ok(Some(v)) => {
                    let res = M::decode(&mut Cursor::new(v.as_slice()))?;
                    debug!("{} received data", self.name);
                    return Ok(res);
                }
            }
        }
    }

    #[inline]
    fn shared_id(&self) -> Uuid {
        self.shared_id
    }
}
