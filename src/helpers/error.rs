use crate::error::BoxError;
use crate::helpers::Identity;
use crate::protocol::{RecordId, Step};
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
        inner: serde_json::Error,
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

    pub fn serialization_error<S: Step>(
        record_id: RecordId,
        step: S,
        inner: serde_json::Error,
    ) -> Error {
        Self::SerializationError {
            record_id,
            step: format!("{:?}", step),
            inner,
        }
    }
}

impl<S: Step> From<SendError<ReceiveRequest<S>>> for Error {
    fn from(source: SendError<ReceiveRequest<S>>) -> Self {
        Self::SendError {
            dest: source.0.channel_id.identity,
            inner: source.to_string().into(),
        }
    }
}

impl<S: Step> From<SendError<(ChannelId<S>, MessageEnvelope)>> for Error {
    fn from(source: SendError<(ChannelId<S>, MessageEnvelope)>) -> Self {
        Self::SendError {
            dest: source.0 .0.identity,
            inner: source.to_string().into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
