use crate::helpers::messaging::SendRequest;
use crate::{
    error::BoxError,
    helpers::{
        messaging::ReceiveRequest,
        network::{ChannelId, MessageChunks},
        Role,
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
    #[error("Failed to send data to the network")]
    NetworkError {
        #[from]
        inner: BoxError,
    },
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
        let err_msg = source.to_string();
        match source.into_inner() {
            Some(inner) => Self::SendError {
                channel: inner.0,
                inner: err_msg.into(),
            },
            None => Self::PollSendError {
                inner: err_msg.into(),
            },
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
