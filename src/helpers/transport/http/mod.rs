pub mod discovery;

mod client;
mod server;
mod transport;

pub use client::MpcHelperClient;
pub use transport::HttpTransport;

use crate::{
    helpers::{HelperIdentity, RoleAssignment, MESSAGE_PAYLOAD_SIZE_BYTES},
    protocol::QueryId,
};
use async_trait::async_trait;
use axum::extract::{FromRequest, RequestParts};
use hyper::header::HeaderName;
use std::str::FromStr;

#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
struct CreateQueryResp {
    query_id: QueryId,
}

#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
struct PrepareQueryBody {
    roles: RoleAssignment,
}

/// name of the `origin` header to use for [`OriginHeader`]
static ORIGIN_HEADER_NAME: HeaderName = HeaderName::from_static("origin");
/// name of the `offset` header to use for [`StepHeaders`]
static OFFSET_HEADER_NAME: HeaderName = HeaderName::from_static("offset");
/// name of the `content-type` header used to get the length of the body, to verify valid `data-size`
static CONTENT_LENGTH_HEADER_NAME: HeaderName = HeaderName::from_static("content-length");

fn get_header<B, H: FromStr>(
    req: &RequestParts<B>,
    header_name: HeaderName,
) -> Result<H, server::Error>
where
    server::Error: From<<H as FromStr>::Err>,
{
    let header_name_string = header_name.to_string();
    req.headers()
        .get(header_name)
        .ok_or(server::Error::MissingHeader(header_name_string))
        .and_then(|header_value| header_value.to_str().map_err(Into::into))
        .and_then(|header_value_str| header_value_str.parse().map_err(Into::into))
}

/// Header indicating the originating `HelperIdentity`.
/// May be replaced in the future with a method with better security
#[cfg_attr(feature = "enable-serde", derive(serde::Deserialize))]
struct OriginHeader {
    origin: HelperIdentity,
}

impl OriginHeader {
    pub(crate) fn add_to(self, req: axum::http::request::Builder) -> axum::http::request::Builder {
        req.header(ORIGIN_HEADER_NAME.clone(), self.origin)
    }
}

#[async_trait]
impl<B: Send> FromRequest<B> for OriginHeader {
    type Rejection = server::Error;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let origin: usize = get_header(req, ORIGIN_HEADER_NAME.clone())?;
        let origin = HelperIdentity::try_from(origin)
            .map_err(|err| server::Error::InvalidHeader(err.into()))?;
        Ok(OriginHeader { origin })
    }
}

/// Headers that are expected on `Step` commands
/// # `content_length`
/// standard HTTP header representing length of entire body. Body length must be a multiple of
/// `MESSAGE_PAYLOAD_SIZE_BYTES`
/// # `offset`
/// For any given batch, their `record_id`s must be known. The first record in the batch will have
/// id `offset`, and subsequent records will be in-order from there.
#[derive(Copy, Clone)]
struct StepHeaders {
    offset: u32,
}

impl StepHeaders {
    pub(crate) fn add_to(self, req: axum::http::request::Builder) -> axum::http::request::Builder {
        req.header(OFFSET_HEADER_NAME.clone(), self.offset)
    }
}

#[async_trait]
impl<B: Send> FromRequest<B> for StepHeaders {
    type Rejection = server::Error;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let content_length: u32 = get_header(req, CONTENT_LENGTH_HEADER_NAME.clone())?;
        let offset: u32 = get_header(req, OFFSET_HEADER_NAME.clone())?;
        // content_length must be aligned with the size of an element
        if content_length as usize % MESSAGE_PAYLOAD_SIZE_BYTES == 0 {
            Ok(StepHeaders { offset })
        } else {
            Err(server::Error::WrongBodyLen {
                body_len: content_length,
                element_size: MESSAGE_PAYLOAD_SIZE_BYTES,
            })
        }
    }
}
