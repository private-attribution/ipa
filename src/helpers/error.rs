use crate::{
    error::BoxError,
    helpers::{
        messaging::ReceiveRequest,
        network::{ChannelId, MessageChunks, MessageEnvelope},
        Role,
    },
    protocol::{RecordId, UniqueStepId},
};
use thiserror::Error;
use tokio::sync::mpsc::error::SendError;
use tokio_util::sync::PollSendError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("An error occurred while sending data to {dest:?}")]
    SendError {
        dest: Role,

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
}

impl Error {
    pub fn send_error<E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>>(
        dest: Role,
        inner: E,
    ) -> Error {
        Self::SendError {
            dest,
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
        step: &UniqueStepId,
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
            dest: source.0.channel_id.role,
            inner: source.to_string().into(),
        }
    }
}

impl From<SendError<(ChannelId, MessageEnvelope)>> for Error {
    fn from(source: SendError<(ChannelId, MessageEnvelope)>) -> Self {
        Self::SendError {
            dest: source.0 .0.role,
            inner: source.to_string().into(),
        }
    }
}

impl From<PollSendError<MessageChunks>> for Error {
    fn from(source: PollSendError<MessageChunks>) -> Self {
        let err_msg = source.to_string();
        match source.into_inner() {
            Some(inner) => Self::SendError {
                dest: inner.0.role,
                inner: err_msg.into(),
            },
            None => Self::PollSendError {
                inner: err_msg.into(),
            },
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
