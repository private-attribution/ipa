pub mod discovery;

mod client;
mod server;
mod transport;

pub use transport::HttpTransport;

use crate::{
    ff::FieldTypeStr,
    helpers::{HelperIdentity, Role, MESSAGE_PAYLOAD_SIZE_BYTES},
};
use async_trait::async_trait;
use axum::extract::{FromRequest, Query, RequestParts};
use hyper::header::HeaderName;
use std::collections::HashMap;
use std::str::FromStr;

#[cfg_attr(feature = "enable-serde", derive(serde::Deserialize))]
struct PrepareQueryParams {
    field_type: String,
}

#[async_trait]
impl<B: Send> FromRequest<B> for PrepareQueryParams {
    type Rejection = server::Error;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Query(pqp) = req.extract::<Query<PrepareQueryParams>>().await?;
        let _ = pqp.field_type.size_in_bytes()?; // confirm that `field_type` is valid
        Ok(pqp)
    }
}

#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
struct PrepareQueryBody {
    helper_positions: [HelperIdentity; 3],
    helpers_to_roles: HashMap<HelperIdentity, Role>,
}

/// name of the `offset` header to use for [`RecordHeaders`]
static OFFSET_HEADER_NAME: HeaderName = HeaderName::from_static("offset");
/// name of the `content-type` header used to get the length of the body, to verify valid `data-size`
static CONTENT_LENGTH_HEADER_NAME: HeaderName = HeaderName::from_static("content-length");

/// Headers that are expected on `Step` commands
/// # `content_length`
/// standard HTTP header representing length of entire body. Body length must be a multiple of
/// `MESSAGE_PAYLOAD_SIZE_BYTES`
/// # `offset`
/// For any given batch, their `record_id`s must be known. The first record in the batch will have
/// id `offset`, and subsequent records will be in-order from there.
#[derive(Copy, Clone)]
struct StepHeaders {
    content_length: u32,
    offset: u32,
}

impl StepHeaders {
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

    pub(crate) fn add_to(self, req: axum::http::request::Builder) -> axum::http::request::Builder {
        req.header(CONTENT_LENGTH_HEADER_NAME.clone(), self.content_length)
            .header(OFFSET_HEADER_NAME.clone(), self.offset)
    }
}

#[async_trait]
impl<B: Send> FromRequest<B> for StepHeaders {
    type Rejection = server::Error;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let content_length: u32 = StepHeaders::get_header(req, CONTENT_LENGTH_HEADER_NAME.clone())?;
        let offset: u32 = StepHeaders::get_header(req, OFFSET_HEADER_NAME.clone())?;
        // content_length must be aligned with the size of an element
        if content_length as usize % MESSAGE_PAYLOAD_SIZE_BYTES == 0 {
            Ok(StepHeaders {
                content_length,
                offset,
            })
        } else {
            Err(server::Error::WrongBodyLen {
                body_len: content_length,
                element_size: MESSAGE_PAYLOAD_SIZE_BYTES,
            })
        }
    }
}

#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
struct StepBody {
    roles_to_helpers: [HelperIdentity; 3],
    chunk: Vec<u8>,
}
