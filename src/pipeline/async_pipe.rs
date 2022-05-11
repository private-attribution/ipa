/// this module mirrors the synchronous pipeline, but with async/await via tokio.
/// requires a workaround `async_trait` to use async functions inside traits
use crate::error::{Error, Res};
use crate::pipeline::hashmap_thread::HashMapCommand;
use crate::proto::pipe::ForwardRequest;
use async_trait::async_trait;
use prost::alloc::vec::Vec as ProstVec;
use prost::Message;
use std::io::Cursor;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time;
use uuid::Uuid;

/// The only difference from `PStep` is the `async fn compute`
#[async_trait]
pub trait AStep {
    type Input;
    type Output;
    async fn compute(
        &self,
        inp: Self::Input,
        helper: Arc<impl THelper + Send + Sync + 'static>,
    ) -> Res<Self::Output>;
    fn unique_id(&self) -> Uuid;
}

/// the only difference from `build_pipeline` is the `async move` block, and the `.await` on
/// `.compute`.
#[macro_export]
macro_rules! build_async_pipeline {
    ($helper:expr, $($step:expr)=>+) => {{
        move |res| async move {
            $(
                let res = $step.compute(res, $helper).await?;
            )*
            Ok(res)
        }
    }};
}

#[async_trait]
pub trait THelper {
    async fn send_to_next<T: Into<ProstVec<u8>> + Send>(&self, key: Uuid, data: T) -> Res<()>;
    async fn send_to_prev<T: Into<ProstVec<u8>> + Send>(&self, key: Uuid, data: T) -> Res<()>;
    async fn receive_from<T: TryFrom<ProstVec<u8>> + Send>(&self, key: Uuid) -> Res<T>
    where
        T::Error: Into<Error>;
}

pub struct ChannelHelper {
    pub next_send_chan: mpsc::Sender<ProstVec<u8>>,
    pub prev_send_chan: mpsc::Sender<ProstVec<u8>>,
    hashmap_chan: mpsc::Sender<HashMapCommand>,
}
impl ChannelHelper {
    #[must_use]
    pub fn new(
        next_send_chan: mpsc::Sender<Vec<u8>>,
        prev_send_chan: mpsc::Sender<Vec<u8>>,
        hashmap_chan: mpsc::Sender<HashMapCommand>,
    ) -> ChannelHelper {
        ChannelHelper {
            next_send_chan,
            prev_send_chan,
            hashmap_chan,
        }
    }

    async fn send_to<T: Into<Vec<u8>>>(
        &self,
        key: Uuid,
        data: T,
        chan: &mpsc::Sender<ProstVec<u8>>,
    ) -> Res<()> {
        let freq = ForwardRequest {
            id: key.to_string(),
            num: data.into(),
        };
        let mut buf = Vec::new();
        buf.reserve(freq.encoded_len());
        // unwrap is safe because `buf` has `encoded_len` reserved
        freq.encode(&mut buf).unwrap();
        chan.send(buf).await.map_err(Error::from)
    }

    pub async fn receive_data(&self, mut recv_chan: mpsc::Receiver<ProstVec<u8>>) {
        while let Some(data) = recv_chan.recv().await {
            match ForwardRequest::decode(&mut Cursor::new(data.as_slice())) {
                Err(err) => {
                    println!("received unexpected message: {}", Error::from(err));
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
                        .hashmap_chan
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
        std::str::from_utf8(&*v).map_or(Err(Error::WrongType), |str| Ok(SendStr(str.to_string())))
    }
}
impl From<SendStr> for ProstVec<u8> {
    fn from(str: SendStr) -> Self {
        str.0.into()
    }
}

#[async_trait]
impl THelper for ChannelHelper {
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
        T::Error: Into<Error>,
    {
        let (tx, rx) = oneshot::channel();
        self.hashmap_chan
            .send(HashMapCommand::Remove(key, tx))
            .await
            .map_err(Error::from)?;
        match rx.await {
            Err(_) => Err(Error::AsyncDeadThread4),
            Ok(None) => {
                println!("nothing in cache, waiting...");
                // basic poll for now; will use watchers in real implementation
                time::sleep(Duration::from_millis(500)).await;
                Box::pin(self.receive_from(key)).await
            }
            Ok(Some(v)) => v.try_into().map_err(Into::into),
        }
    }
}

/// The only difference from `Pipeline` is the `async fn pipeline`
#[async_trait]
pub trait APipeline<Input, Output> {
    async fn pipeline(&self, inp: Input) -> Res<Output>;
}
