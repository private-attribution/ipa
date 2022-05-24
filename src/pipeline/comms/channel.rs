use crate::pipeline::comms::Comms;
use crate::pipeline::error::{Error, Res};
use crate::pipeline::hashmap_thread::{HashMapCommand, HashMapHandler};
use crate::proto::pipe::ForwardRequest;
use async_trait::async_trait;
use prost::alloc::vec::Vec as ProstVec;
use prost::Message;
use std::future::Future;
use std::io::Cursor;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::{time, try_join};
use uuid::Uuid;

pub struct Channel {
    pub next_send_chan: mpsc::Sender<ProstVec<u8>>,
    pub prev_send_chan: mpsc::Sender<ProstVec<u8>>,
    hashmap_send: mpsc::Sender<HashMapCommand>,
}
impl Channel {
    #[must_use]
    pub fn new(
        next_send_chan: mpsc::Sender<ProstVec<u8>>,
        prev_send_chan: mpsc::Sender<ProstVec<u8>>,
        hashmap_send: mpsc::Sender<HashMapCommand>,
    ) -> Channel {
        Channel {
            next_send_chan,
            prev_send_chan,
            hashmap_send,
        }
    }

    pub fn all_comms() -> (
        Arc<Channel>,
        Arc<Channel>,
        Arc<Channel>,
        impl Future<Output = Res<()>>,
    ) {
        let (h1_send, h1_recv) = mpsc::channel(32);
        let (h2_send, h2_recv) = mpsc::channel(32);
        let (h3_send, h3_recv) = mpsc::channel(32);

        let (h1_hashmap_send, h1_hashmap_recv) = mpsc::channel(32);
        let (h2_hashmap_send, h2_hashmap_recv) = mpsc::channel(32);
        let (h3_hashmap_send, h3_hashmap_recv) = mpsc::channel(32);
        let h1_hashmap = HashMapHandler::new(h1_hashmap_recv);
        let h2_hashmap = HashMapHandler::new(h2_hashmap_recv);
        let h3_hashmap = HashMapHandler::new(h3_hashmap_recv);

        let h1 = Arc::new(Channel::new(
            h2_send.clone(),
            h3_send.clone(),
            h1_hashmap_send,
        ));
        let h2 = Arc::new(Channel::new(
            h3_send.clone(),
            h1_send.clone(),
            h2_hashmap_send,
        ));
        let h3 = Arc::new(Channel::new(
            h1_send.clone(),
            h2_send.clone(),
            h3_hashmap_send,
        ));
        drop(h1_send);
        drop(h2_send);
        drop(h3_send);

        let run = {
            let chan1 = h1.clone();
            let chan2 = h2.clone();
            let chan3 = h3.clone();
            async move {
                let h1_recvd = chan1.receive_data(h1_recv);
                let h1_run_hashmap = h1_hashmap.run();
                let h2_recvd = chan2.receive_data(h2_recv);
                let h2_run_hashmap = h2_hashmap.run();
                let h3_recvd = chan3.receive_data(h3_recv);
                let h3_run_hashmap = h3_hashmap.run();
                try_join!(
                    tokio::spawn(h1_recvd),
                    tokio::spawn(h1_run_hashmap),
                    tokio::spawn(h2_recvd),
                    tokio::spawn(h2_run_hashmap),
                    tokio::spawn(h3_recvd),
                    tokio::spawn(h3_run_hashmap)
                )?;
                Ok(())
            }
        };
        (h1, h2, h3, run)
    }

    async fn send_to<T: Into<ProstVec<u8>>>(
        &self,
        key: Uuid,
        data: T,
        chan: &mpsc::Sender<ProstVec<u8>>,
    ) -> Res<()> {
        let freq = ForwardRequest {
            id: key.to_string(),
            num: data.into(),
        };
        let mut buf = ProstVec::new();
        buf.reserve(freq.encoded_len());
        // unwrap is safe because `buf` has `encoded_len` reserved
        freq.encode(&mut buf).unwrap();
        chan.send(buf).await?;
        Ok(())
    }

    // TODO: why do you need `self: Arc<Self>` here, where `&self` does not work?
    pub async fn receive_data(&self, mut recv_chan: mpsc::Receiver<ProstVec<u8>>) {
        while let Some(data) = recv_chan.recv().await {
            match ForwardRequest::decode(&mut Cursor::new(data.as_slice())) {
                Err(err) => {
                    println!("received unexpected message: {}", Error::DecodeError(err));
                }
                Ok(decoded) => {
                    let decoded_uuid = match Uuid::from_str(decoded.id.as_str()) {
                        Err(err) => {
                            println!("message id was not a uuid: {}", err);
                            continue;
                        }
                        Ok(uuid) => uuid,
                    };
                    let (tx, rx) = oneshot::channel();
                    let sent = self
                        .hashmap_send
                        .send(HashMapCommand::Write(decoded_uuid, decoded.num, tx))
                        .await;
                    if sent.is_err() {
                        println!("could not send message to hashmap: {}", sent.unwrap_err());
                    }
                    let res = rx.await;
                    if res.is_err() {
                        println!(
                            "could not receive response from hashmap: {}",
                            res.unwrap_err()
                        );
                    }
                }
            }
        }
    }
}

pub struct SendStr(pub String);
impl Deref for SendStr {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl TryFrom<ProstVec<u8>> for SendStr {
    type Error = Error;

    fn try_from(v: ProstVec<u8>) -> Result<Self, Self::Error> {
        let str = std::str::from_utf8(&*v)?;
        Ok(SendStr(str.to_string()))
    }
}
impl From<SendStr> for ProstVec<u8> {
    fn from(str: SendStr) -> Self {
        str.0.into()
    }
}

#[async_trait]
impl Comms for Channel {
    async fn send_to_next<T: Into<ProstVec<u8>> + Send>(&self, key: Uuid, data: T) -> Res<()> {
        self.send_to(key, data, &self.next_send_chan).await?;
        println!("sent data to next helper: {key}");
        Ok(())
    }

    async fn send_to_prev<T: Into<ProstVec<u8>> + Send>(&self, key: Uuid, data: T) -> Res<()> {
        self.send_to(key, data, &self.prev_send_chan).await?;
        println!("sent data to prev helper: {key}");
        Ok(())
    }
    async fn receive_from<T: TryFrom<ProstVec<u8>> + Send>(&self, key: Uuid) -> Res<T>
    where
        Error: From<T::Error>,
    {
        let (tx, rx) = oneshot::channel();
        self.hashmap_send
            .send(HashMapCommand::Remove(key, tx))
            .await?;
        match rx.await {
            Err(err) => Err(err.into()),
            Ok(None) => {
                println!("nothing in cache, waiting...");
                // basic poll for now; will use watchers in real implementation
                time::sleep(Duration::from_millis(500)).await;
                Box::pin(self.receive_from(key)).await
            }
            Ok(Some(v)) => {
                let res = v.try_into()?;
                Ok(res)
            }
        }
    }
}
