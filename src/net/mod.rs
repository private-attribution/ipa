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
use std::str::FromStr;

use crate::net::server::MpcServerError;
use crate::protocol::{QueryId, RecordId};
use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::{FromRequest, RequestParts};
use axum::http::header::HeaderName;

/// name of the `offset` header to use for [`RecordHeaders`]
static OFFSET_HEADER_NAME: HeaderName = HeaderName::from_static("offset");
/// name of the `data_size` header to use for [`RecordHeaders`]
static DATA_SIZE_HEADER_NAME: HeaderName = HeaderName::from_static("data-size");

/// Headers that are expected on requests involving a batch of records.
/// # `offset`
/// For any given batch, their record_ids must be known. The first record in the batch will have id
/// `offset`, and subsequent records will be in-order from there.
/// # `data_size`
/// the batch will be transmitted as a single `Bytes` block, and the receiver will need to know how
/// to divide up the block into individual records. `data_size` represents the number of bytes each
/// record consists of
pub struct RecordHeaders {
    offset: u32,
    data_size: u32,
}

impl RecordHeaders {
    fn get_header<B, H: FromStr>(
        req: &RequestParts<B>,
        header_name: HeaderName,
    ) -> Result<H, MpcServerError>
    where
        MpcServerError: From<<H as FromStr>::Err>,
    {
        let header_name_string = header_name.to_string();
        req.headers()
            .get(header_name)
            .ok_or(MpcServerError::MissingHeader(header_name_string))
            .and_then(|header_value| header_value.to_str().map_err(Into::into))
            .and_then(|header_value_str| header_value_str.parse().map_err(Into::into))
    }

    pub(crate) fn add_to(&self, req: axum::http::request::Builder) -> axum::http::request::Builder {
        req.header(OFFSET_HEADER_NAME.clone(), self.offset)
            .header(DATA_SIZE_HEADER_NAME.clone(), self.data_size)
    }
}

#[async_trait]
impl<B: Send> FromRequest<B> for RecordHeaders {
    type Rejection = MpcServerError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let offset: u32 = RecordHeaders::get_header(req, OFFSET_HEADER_NAME.clone())?;
        let data_size: u32 = RecordHeaders::get_header(req, DATA_SIZE_HEADER_NAME.clone())?;
        Ok(RecordHeaders { offset, data_size })
    }
}

/// After receiving a batch of records from the network, package it into this [`BufferedMessages`]
/// and pass it to the network layer for processing, and to pass on to the messaging layer
#[derive(Debug, PartialEq, Eq)]
#[allow(dead_code)] // TODO: to be used in next PR
pub struct BufferedMessages<S> {
    query_id: QueryId,
    step: S,
    offset: u32,
    data_size: u32,
    body: Bytes,
}

#[derive(Debug)]
#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
#[allow(dead_code)] // TODO: this should be used after breaking down the [`BufferedMessages`]
pub struct MessageEnvelope {
    record_id: RecordId,
    message: Box<u8>,
}
