use thiserror::Error;

use crate::{
    helpers::{
        buffers::{DeserializeError, EndOfStreamError},
        ChannelId, TotalRecords, TransportIdentity,
    },
    protocol::RecordId,
};

/// An error raised by the IPA supporting infrastructure.
#[derive(Error, Debug)]
pub enum Error<I: TransportIdentity> {
    #[error("Received end of stream from {origin:?}/{step}: {inner}")]
    EndOfStream {
        origin: I,
        step: String,
        inner: EndOfStreamError,
    },
    #[error("Deserialization error when receiving from {origin:?}/{step}: {inner}")]
    DeserializeFailed {
        origin: I,
        step: String,
        inner: DeserializeError,
    },
    #[error("record ID {record_id:?} is out of range for {channel_id:?} (expected {total_records:?} records)")]
    TooManyRecords {
        record_id: RecordId,
        channel_id: ChannelId<I>,
        total_records: TotalRecords,
    },
}
