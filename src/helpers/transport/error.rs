use crate::{
    error::BoxError,
    helpers::{transport::TransportCommand, HelperIdentity},
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
    #[error("command {} failed to send data for query {}: {inner}",
    .command_name.unwrap_or("<missing_command>"),
    if let Some(q) =.query_id { q.as_ref() } else { "<missing query id>" }
    )]
    SendFailed {
        command_name: Option<&'static str>,
        query_id: Option<QueryId>,
        #[source]
        inner: BoxError,
    },
    #[error("attempted to subscribe to commands for query id {}, but there is already a previous subscriber", .query_id.as_ref())]
    PreviouslySubscribed { query_id: QueryId },
    #[error("encountered unknown helper: {0:?}")]
    UnknownHelper(HelperIdentity),
    #[error("command {command_name} can only be used by external entities")]
    ExternalCommandSent { command_name: &'static str },
    #[error("could not read from input stream: {0}")]
    InputInvalid(#[from] std::io::Error),
}

impl From<tokio_util::sync::PollSendError<TransportCommand>> for Error {
    fn from(source: tokio_util::sync::PollSendError<TransportCommand>) -> Self {
        let (command_name, query_id) = source
            .into_inner()
            .map_or((None, None), |inner| (Some(inner.name()), inner.query_id()));

        Self::SendFailed {
            command_name,
            query_id,
            inner: "channel closed".into(),
        }
    }
}

#[cfg(any(test, feature = "test-fixture"))]
impl From<tokio::sync::mpsc::error::SendError<TransportCommand>> for Error {
    fn from(source: tokio::sync::mpsc::error::SendError<TransportCommand>) -> Self {
        Self::SendFailed {
            command_name: Some(source.0.name()),
            query_id: source.0.query_id(),
            inner: "channel closed".into(),
        }
    }
}
