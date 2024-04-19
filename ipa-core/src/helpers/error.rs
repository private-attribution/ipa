use thiserror::Error;

use crate::{
    error::BoxError,
    helpers::{ChannelId, TotalRecords, TransportIdentity},
    protocol::RecordId,
};

/// An error raised by the IPA supporting infrastructure.
#[derive(Error, Debug)]
pub enum Error<I: TransportIdentity> {
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
    #[error("record ID {record_id:?} is out of range for {channel_id:?} (expected {total_records:?} records)")]
    TooManyRecords {
        record_id: RecordId,
        channel_id: ChannelId<I>,
        total_records: TotalRecords,
    },
}
