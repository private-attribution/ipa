// need this to allow MessageEnvelope to have custom serde bounds
#![allow(clippy::type_repetition_in_bounds)]

mod client;
mod data;
mod server;

pub use client::{MpcHandle, MpcHttpConnection as Client};
pub use data::Command;
#[cfg(feature = "self-signed-certs")]
pub use server::tls_config_from_self_signed_cert;
pub use server::{bind as bind_mpc_helper_server, router as mpc_helper_router, BindTarget};

use crate::helpers::mesh::Message;
use crate::protocol::RecordId;

#[derive(Debug)]
#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MessageEnvelope<M: Message> {
    record_id: RecordId,
    #[serde(bound(deserialize = "M: serde::de::DeserializeOwned"))]
    message: M,
}
