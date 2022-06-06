pub mod channel;

use crate::pipeline::Result;
use async_trait::async_trait;
use uuid::Uuid;

#[derive(Debug)]
pub enum Target {
    Next,
    Prev,
}

#[async_trait]
pub trait Comms: Send + Sync + 'static {
    async fn send_to<M: prost::Message>(&self, target: Target, data: M) -> Result<()>;
    async fn receive_from<M: prost::Message + Default>(&self) -> Result<M>;
    fn shared_id(&self) -> Uuid;
}
