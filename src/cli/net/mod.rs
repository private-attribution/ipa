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

use crate::protocol::RecordId;
use axum::http::header::HeaderName;

pub(crate) const OFFSET_HEADER_NAME: HeaderName = HeaderName::from_static("offset");
pub(crate) const DATA_SIZE_HEADER_NAME: HeaderName = HeaderName::from_static("data-size");

#[derive(Debug)]
#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MessageEnvelope {
    record_id: RecordId,
    message: Box<u8>,
}
