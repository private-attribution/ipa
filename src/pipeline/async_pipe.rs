/// this module mirrors the synchronous pipeline, but with async/await via tokio.
/// requires a workaround `async_trait` to use async functions inside traits
use crate::error::{Error, Res};
use crate::proto::pipe::ForwardRequest;
use async_trait::async_trait;
use dashmap::DashMap;
use prost::alloc::vec::Vec as ProstVec;
use prost::Message;
use std::collections::hash_map::RandomState;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time;
use uuid::Uuid;

/// The only difference from `PStep` is the `async fn compute`
#[async_trait(?Send)]
pub trait AStep {
    type Input;
    type Output;
    async fn compute(
        &self,
        inp: Self::Input,
        helper: &(impl THelper + 'static),
    ) -> Res<Self::Output>;
    fn unique_id(&self) -> &Uuid;
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

#[async_trait(?Send)]
pub trait THelper {
    async fn send_to_next<T: Into<ProstVec<u8>>>(&self, key: String, data: T) -> Res<()>;
    async fn send_to_prev<T: Into<ProstVec<u8>>>(&self, key: String, data: T) -> Res<()>;
    async fn receive_from<T: TryFrom<ProstVec<u8>>>(&self, key: String) -> Res<T>
    where
        T::Error: Into<Error>;
}

pub struct ChannelHelper {
    pub next_send_chan: Sender<ProstVec<u8>>,
    pub prev_send_chan: Sender<ProstVec<u8>>,
    pub recv_chan: Receiver<ProstVec<u8>>,
    cache: Arc<DashMap<String, ProstVec<u8>, RandomState>>,
}
impl ChannelHelper {
    #[must_use]
    pub fn new(
        next_send_chan: Sender<Vec<u8>>,
        prev_send_chan: Sender<Vec<u8>>,
        recv_chan: Receiver<Vec<u8>>,
    ) -> ChannelHelper {
        ChannelHelper {
            next_send_chan,
            prev_send_chan,
            recv_chan,
            cache: Arc::new(DashMap::with_capacity(32)),
        }
    }

    async fn send_to<T: Into<Vec<u8>>>(
        &self,
        key: String,
        data: T,
        chan: &Sender<ProstVec<u8>>,
    ) -> Res<()> {
        let freq = ForwardRequest {
            id: key,
            num: data.into(),
        };
        let mut buf = Vec::new();
        buf.reserve(freq.encoded_len());
        // unwrap is safe because `buf` has `encoded_len` reserved
        freq.encode(&mut buf).unwrap();
        chan.send(buf).await.map_err(Error::from)
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

#[async_trait(?Send)]
impl THelper for ChannelHelper {
    async fn send_to_next<T: Into<ProstVec<u8>>>(&self, key: String, data: T) -> Res<()> {
        self.send_to(key, data, &self.next_send_chan).await
    }

    async fn send_to_prev<T: Into<ProstVec<u8>>>(&self, key: String, data: T) -> Res<()> {
        self.send_to(key, data, &self.prev_send_chan).await
    }

    async fn receive_from<T: TryFrom<ProstVec<u8>>>(&self, key: String) -> Res<T>
    where
        T::Error: Into<Error>,
    {
        match self.cache.remove(&key) {
            None => {
                // basic poll for now; will use watchers in real implementation
                time::sleep(Duration::from_millis(500)).await;
                Box::pin(async move { self.receive_from(key).await }).await
            }
            Some((_, v)) => v.try_into().map_err(Into::into),
        }
    }
}

/// The only difference from `Pipeline` is the `async fn pipeline`
#[async_trait(?Send)]
pub trait APipeline<Input, Output, H: THelper> {
    async fn pipeline(&self, inp: Input) -> Res<Output>;
}
