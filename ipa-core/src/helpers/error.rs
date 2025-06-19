use thiserror::Error;

use crate::{
    helpers::{
        ChannelId, TotalRecords, TransportIdentity,
        buffers::{DeserializeError, EndOfStreamError},
    },
    protocol::RecordId,
};

/// An error raised by the IPA supporting infrastructure.
#[derive(Error, Debug)]
pub enum Error<I: TransportIdentity> {
    #[error("Received end of stream from {channel_id:?}: {inner}")]
    EndOfStream {
        channel_id: ChannelId<I>,
        inner: EndOfStreamError,
    },
    #[error("Deserialization error when receiving from {channel_id:?}: {inner}")]
    DeserializeFailed {
        channel_id: ChannelId<I>,
        inner: DeserializeError,
    },
    #[error(
        "record ID {record_id:?} is out of range for {channel_id:?} (expected {total_records:?} records)"
    )]
    TooManyRecords {
        record_id: RecordId,
        channel_id: ChannelId<I>,
        total_records: TotalRecords,
    },
}
