use crate::error::BoxError;
use crate::helpers::Identity;
use crate::protocol::{RecordId, UniqueStepId};
use thiserror::Error;
use tokio::sync::mpsc::error::SendError;

use crate::helpers::fabric::{ChannelId, MessageEnvelope};
use crate::helpers::messaging::ReceiveRequest;

#[derive(Error, Debug)]
pub enum Error {
    #[error("An error occurred while sending data to {dest:?}")]
    SendError {
        dest: Identity,

        #[source]
        inner: BoxError,
    },
    #[error("An error occurred while receiving data from {source:?}")]
    ReceiveError {
        source: Identity,
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
        dest: Identity,
        inner: E,
    ) -> Error {
        Self::SendError {
            dest,
            inner: inner.into(),
        }
    }

    pub fn receive_error<E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>>(
        source: Identity,
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
            dest: source.0.channel_id.identity,
            inner: source.to_string().into(),
        }
    }
}

impl From<SendError<(ChannelId, MessageEnvelope)>> for Error {
    fn from(source: SendError<(ChannelId, MessageEnvelope)>) -> Self {
        Self::SendError {
            dest: source.0 .0.identity,
            inner: source.to_string().into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
