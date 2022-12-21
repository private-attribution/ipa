use crate::{
    helpers::transport::{
        CreateQueryData, MulData, NetworkEventData, PrepareQueryData, StartMulData,
        TransportCommand, TransportCommandData,
    },
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
            Some(TransportCommand::CreateQuery(_)) => (Some(CreateQueryData::name()), None),
            Some(TransportCommand::PrepareQuery(PrepareQueryData { query_id, .. })) => {
                (Some(PrepareQueryData::name()), Some(query_id))
            }
            Some(TransportCommand::StartMul(StartMulData { query_id, .. })) => {
                (Some(StartMulData::name()), Some(query_id))
            }
            Some(TransportCommand::Mul(MulData { query_id, .. })) => {
                (Some(MulData::name()), Some(query_id))
            }
            Some(TransportCommand::NetworkEvent(NetworkEventData { query_id, .. })) => {
                (Some(NetworkEventData::name()), Some(query_id))
            }
            None => (None, None),
        };
        Self::SendFailed {
            command_name,
            query_id,
        }
    }
}
