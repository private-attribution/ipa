// need this to allow MessageEnvelope to have custom serde bounds
#![allow(clippy::type_repetition_in_bounds)]

mod client;
mod server;

pub mod discovery;
pub mod http_network;

pub use client::MpcHelperClient;
#[cfg(feature = "self-signed-certs")]
pub use server::tls_config_from_self_signed_cert;
pub use server::{BindTarget, MessageSendMap, MpcHelperServer};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use crate::{
    helpers::{network::ChannelId, MESSAGE_PAYLOAD_SIZE_BYTES},
    net::server::MpcHelperServerError,
};
use async_trait::async_trait;
use axum::{
    extract::{FromRequest, RequestParts},
    http::header::HeaderName,
};

/// name of the `offset` header to use for [`RecordHeaders`]
static OFFSET_HEADER_NAME: HeaderName = HeaderName::from_static("offset");
/// name of the `content-type` header used to get the length of the body, to verify valid `data-size`
static CONTENT_LENGTH_HEADER_NAME: HeaderName = HeaderName::from_static("content-length");

/// Headers that are expected on requests involving a batch of records.
/// # `content_length`
/// standard HTTP header representing length of entire body. Body length must be a multiple of
/// `MESSAGE_PAYLOAD_SIZE_BYTES`
/// # `offset`
/// For any given batch, their `record_id`s must be known. The first record in the batch will have id
/// `offset`, and subsequent records will be in-order from there.
#[derive(Copy, Clone)]
pub struct RecordHeaders {
    content_length: u32,
    offset: u32,
}

impl RecordHeaders {
    fn get_header<B, H: FromStr>(
        req: &RequestParts<B>,
        header_name: HeaderName,
    ) -> Result<H, MpcHelperServerError>
    where
        MpcHelperServerError: From<<H as FromStr>::Err>,
    {
        let header_name_string = header_name.to_string();
        req.headers()
            .get(header_name)
            .ok_or(MpcHelperServerError::MissingHeader(header_name_string))
            .and_then(|header_value| header_value.to_str().map_err(Into::into))
            .and_then(|header_value_str| header_value_str.parse().map_err(Into::into))
    }

    pub(crate) fn add_to(self, req: axum::http::request::Builder) -> axum::http::request::Builder {
        req.header(CONTENT_LENGTH_HEADER_NAME.clone(), self.content_length)
            .header(OFFSET_HEADER_NAME.clone(), self.offset)
    }
}

#[async_trait]
impl<B: Send> FromRequest<B> for RecordHeaders {
    type Rejection = MpcHelperServerError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let content_length: u32 =
            RecordHeaders::get_header(req, CONTENT_LENGTH_HEADER_NAME.clone())?;
        let offset: u32 = RecordHeaders::get_header(req, OFFSET_HEADER_NAME.clone())?;
        // content_length must be aligned with the size of an element
        if content_length as usize % MESSAGE_PAYLOAD_SIZE_BYTES == 0 {
            Ok(RecordHeaders {
                content_length,
                offset,
            })
        } else {
            Err(MpcHelperServerError::WrongBodyLen {
                body_len: content_length,
                element_size: MESSAGE_PAYLOAD_SIZE_BYTES,
            })
        }
    }
}

/// Keeps track of the last seen message for every [`ChannelId`]. This enables the server to ensure
/// that messages arrive in-order. This solution is a temporary one intended to be removed once
/// messages arrive in one stream, where ordering will be handled by http.
/// TODO (ts): remove this when streaming solution is complete
#[derive(Clone)]
pub(crate) struct LastSeenMessages {
    messages: Arc<Mutex<HashMap<ChannelId, u32>>>,
}

impl LastSeenMessages {
    /// ensures that incoming message follows last seen message
    /// # Panics
    /// if messages arrive out of order
    pub fn update_in_place(&self, channel_id: &ChannelId, next_seen: u32) {
        let mut messages = self.messages.lock().unwrap();
        let last_seen = messages.entry(channel_id.clone()).or_default();
        if *last_seen == next_seen {
            *last_seen += 1;
        } else {
            panic!("out-of-order delivery of data for role:{}, step:{}: expected index {last_seen}, but found {next_seen}", channel_id.role.as_ref(), channel_id.step.as_ref());
        }
    }
}

impl Default for LastSeenMessages {
    fn default() -> Self {
        Self {
            messages: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
