pub mod channel;

use crate::pipeline::error::{Error, Res};
use async_trait::async_trait;
use prost::alloc::vec::Vec as ProstVec;
use uuid::Uuid;

#[async_trait]
pub trait Comms {
    async fn send_to_next<T: Into<ProstVec<u8>> + Send>(&self, key: Uuid, data: T) -> Res<()>;
    async fn send_to_prev<T: Into<ProstVec<u8>> + Send>(&self, key: Uuid, data: T) -> Res<()>;
    async fn receive_from<T: TryFrom<ProstVec<u8>> + Send>(&self, key: Uuid) -> Res<T>
    where
        Error: From<T::Error>;
}
