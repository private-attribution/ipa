use crate::{
    error::BoxError,
    helpers::{
        messaging::{ReceiveRequest, SendRequest},
        network::{ChannelId, MessageChunks},
        transport, HelperIdentity, Role,
    },
    net::MpcHelperServerError,
    protocol::{RecordId, Step},
};
use thiserror::Error;
use tokio::sync::mpsc::error::SendError;
use tokio_util::sync::PollSendError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("An error occurred while sending data to {channel:?}: {inner}")]
    SendError {
        channel: ChannelId,

        #[source]
        inner: BoxError,
    },
    #[error("An error occurred while sending data to unknown helper")]
    PollSendError {
        #[source]
        inner: BoxError,
    },
    #[error("An error occurred while receiving data from {source:?}")]
    ReceiveError {
        source: Role,
        #[source]
        inner: BoxError,
    },
    #[error("An error occurred while serializing or deserializing data for {record_id:?} and step {step}")]
    SerializationError {
        record_id: RecordId,
        step: String,
        #[source]
        inner: BoxError,
    },
    #[error("Encountered unknown identity {}", .0.to_string())]
    UnknownIdentity(HelperIdentity),
    #[error("identity had invalid format: {0}")]
    InvalidIdentity(#[from] hyper::http::uri::InvalidUri),
    #[error("Failed to send command on the transport: {0}")]
    TransportError(#[from] transport::Error),
    #[error("server encountered an error: {0}")]
    ServerError(#[from] MpcHelperServerError),
}

impl Error {
    pub fn send_error<E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>>(
        channel: ChannelId,
        inner: E,
    ) -> Error {
        Self::SendError {
            channel,
            inner: inner.into(),
        }
    }

    pub fn receive_error<E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>>(
        source: Role,
        inner: E,
    ) -> Error {
        Self::ReceiveError {
            source,
            inner: inner.into(),
        }
    }

    #[must_use]
    pub fn serialization_error<E: Into<BoxError>>(
        record_id: RecordId,
        step: &Step,
        inner: E,
    ) -> Error {
        Self::SerializationError {
            record_id,
            step: String::from(step.as_ref()),
            inner: inner.into(),
        }
    }
}

impl From<SendError<ReceiveRequest>> for Error {
    fn from(source: SendError<ReceiveRequest>) -> Self {
        Self::SendError {
            channel: source.0.channel_id,
            inner: "channel closed".into(),
        }
    }
}

impl From<SendError<SendRequest>> for Error {
    fn from(source: SendError<SendRequest>) -> Self {
        Self::SendError {
            channel: source.0 .0,
            inner: "channel closed".into(),
        }
    }
}

impl From<PollSendError<MessageChunks>> for Error {
    fn from(source: PollSendError<MessageChunks>) -> Self {
        let inner = source.to_string().into();
        match source.into_inner() {
            Some((channel, _)) => Self::SendError { channel, inner },
            None => Self::PollSendError { inner },
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
