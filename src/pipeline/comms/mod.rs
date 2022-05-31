pub mod channel;

use crate::pipeline::error::Res;
use async_trait::async_trait;
use uuid::Uuid;

#[derive(Debug)]
pub enum Target {
    Next,
    Prev,
}

#[async_trait]
pub trait Comms {
    async fn send_to<M: prost::Message>(&self, target: Target, data: M) -> Res<()>;
    async fn receive_from<M: prost::Message + Default>(&self) -> Res<M>;
    fn shared_id(&self) -> Uuid;
}
