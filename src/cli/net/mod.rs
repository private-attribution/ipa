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

use crate::cli::net::server::MpcServerError;
use crate::protocol::{QueryId, RecordId};
use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::{FromRequest, RequestParts};
use axum::http::header::HeaderName;

static OFFSET_HEADER_NAME: HeaderName = HeaderName::from_static("offset");
static DATA_SIZE_HEADER_NAME: HeaderName = HeaderName::from_static("data-size");

pub struct RecordHeaders {
    offset: usize,
    data_size: usize,
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
        let offset: usize = RecordHeaders::get_header(req, OFFSET_HEADER_NAME.clone())?;
        let data_size: usize = RecordHeaders::get_header(req, DATA_SIZE_HEADER_NAME.clone())?;
        Ok(RecordHeaders { offset, data_size })
    }
}

#[derive(Debug, PartialEq, Eq)]
#[allow(dead_code)] // to be used in next PR
pub struct BufferedMessages<S> {
    query_id: QueryId,
    step: S,
    offset: usize,
    data_size: usize,
    body: Bytes,
}

#[derive(Debug)]
#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MessageEnvelope {
    record_id: RecordId,
    message: Box<u8>,
}
