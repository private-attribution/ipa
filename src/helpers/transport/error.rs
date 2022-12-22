use crate::{
    helpers::transport::{NetworkEventData, TransportCommand, TransportCommandData},
    protocol::QueryId,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("command {command_name} failed to respond to callback for query_id {}", .query_id.as_ref())]
    CallbackFailed {
        command_name: &'static str,
        query_id: QueryId,
    },
    /// TODO: this error may return "missing" data due to nature of `SendPollError`. This should be
    ///       improved
    #[error("command {} failed to send data for query {}",
    .command_name.unwrap_or("<missing_command>"),
    if let Some(q) =.query_id { q.as_ref() } else { "<missing query id>" }
    )]
    SendFailed {
        command_name: Option<&'static str>,
        query_id: Option<QueryId>,
    },
    #[error("attempted to subscribe to commands for query id {}, but there is already a previous subscriber", .query_id.as_ref())]
    PreviouslySubscribed { query_id: QueryId },
}

impl From<tokio_util::sync::PollSendError<TransportCommand>> for Error {
    fn from(source: tokio_util::sync::PollSendError<TransportCommand>) -> Self {
        let (command_name, query_id) = match source.into_inner() {
            // TODO: this is not optimal, requires matching for every command type
            Some(TransportCommand::NetworkEvent(data)) => {
                (Some(NetworkEventData::name()), Some(data.query_id))
            }
            None => (None, None),
        };
        Self::SendFailed {
            command_name,
            query_id,
        }
    }
}

#[cfg(any(test, feature = "test-fixture"))]
impl From<tokio::sync::mpsc::error::SendError<TransportCommand>> for Error {
    fn from(_value: tokio::sync::mpsc::error::SendError<TransportCommand>) -> Self {
        Self::SendFailed {
            command_name: Some("fixme"),
            query_id: Some(QueryId),
        }
    }
}
