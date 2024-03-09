use thiserror::Error;

use crate::{
    error::BoxError,
    helpers::{ChannelId, HelperChannelId, HelperIdentity, Role, TotalRecords, TransportIdentity},
    protocol::{step::Gate, RecordId},
};

/// An error raised by the IPA supporting infrastructure.
#[derive(Error, Debug)]
pub enum Error<I: TransportIdentity> {
    #[error("An error occurred while sending data to {channel:?}: {inner}")]
    SendError {
        channel: ChannelId<I>,

        #[source]
        inner: BoxError,
    },
    #[error("An error occurred while sending data to unknown helper: {inner}")]
    PollSendError {
        #[source]
        inner: BoxError,
    },
    #[error("An error occurred while receiving data from {source:?}/{step}: {inner}")]
    ReceiveError {
        source: I,
        step: String,
        #[source]
        inner: BoxError,
    },
    #[error("Expected to receive {record_id:?} but hit end of stream")]
    EndOfStream {
        // TODO(mt): add more fields, like step and role.
        record_id: RecordId,
    },
    #[error("An error occurred while serializing or deserializing data for {record_id:?} and step {step}: {inner}")]
    SerializationError {
        record_id: RecordId,
        step: String,
        #[source]
        inner: BoxError,
    },
    #[error("Encountered unknown identity {0:?}")]
    UnknownIdentity(HelperIdentity),
    #[error("record ID {record_id:?} is out of range for {channel_id:?} (expected {total_records:?} records)")]
    TooManyRecords {
        record_id: RecordId,
        channel_id: ChannelId<I>,
        total_records: TotalRecords,
    },
}

impl Error<Role> {
    pub fn send_error<E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>>(
        channel: HelperChannelId,
        inner: E,
    ) -> Self {
        Self::SendError {
            channel,
            inner: inner.into(),
        }
    }

    #[must_use]
    pub fn serialization_error<E: Into<BoxError>>(
        record_id: RecordId,
        gate: &Gate,
        inner: E,
    ) -> Self {
        Self::SerializationError {
            record_id,
            step: String::from(gate.as_ref()),
            inner: inner.into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error<Role>>;
