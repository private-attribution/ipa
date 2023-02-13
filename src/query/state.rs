use crate::helpers::messaging::Gateway;
use crate::helpers::query::QueryConfig;
use crate::protocol::QueryId;
use crate::query::ProtocolResult;
use crate::task::JoinHandle;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The status of query processing
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub enum QueryStatus {
    /// Only query running on the coordinator helper can be in this state. Means that coordinator
    /// sent out requests to other helpers and asked them to assume a given role for this query.
    /// Coordinator is currently awaiting response from both peers.
    Preparing,
    /// Mesh network is established between helpers and they are ready to send and receive
    /// messages
    AwaitingInputs,
    /// Query is being executed and can be interrupted by request.
    Running,
    /// Task is created to await completion of a query.
    AwaitingCompletion,
}

impl From<&QueryState> for QueryStatus {
    fn from(source: &QueryState) -> Self {
        match source {
            QueryState::Empty => panic!("Query cannot be in the empty state"),
            QueryState::Preparing(_) => QueryStatus::Preparing,
            QueryState::AwaitingInputs(_, _) => QueryStatus::AwaitingInputs,
            QueryState::Running(_) => QueryStatus::Running,
            QueryState::AwaitingCompletion => QueryStatus::AwaitingCompletion,
        }
    }
}

/// TODO: a macro would be very useful here to keep it in sync with `QueryStatus`
pub enum QueryState {
    Empty,
    Preparing(QueryConfig),
    AwaitingInputs(QueryConfig, Gateway),
    Running(JoinHandle<Box<dyn ProtocolResult>>),
    AwaitingCompletion,
}

impl QueryState {
    pub fn transition(cur_state: &Self, new_state: Self) -> Result<Self, StateError> {
        use {QueryState::AwaitingInputs, QueryState::Empty, QueryState::Preparing};

        match (cur_state, &new_state) {
            // If query is not running, coordinator initial state is preparing
            // and followers initial state is awaiting inputs
            (Empty, Preparing(_) | AwaitingInputs(_, _)) | (Preparing(_), AwaitingInputs(_, _)) => {
                Ok(new_state)
            }
            (_, Preparing(_)) => Err(StateError::AlreadyRunning),
            (_, _) => Err(StateError::InvalidState {
                from: cur_state.into(),
                to: QueryStatus::from(&new_state),
            }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("Query is already running")]
    AlreadyRunning,
    #[error("Cannot transition from state {from:?} to state {to:?}")]
    InvalidState { from: QueryStatus, to: QueryStatus },
}

/// Keeps track of queries running on this helper.
pub struct RunningQueries {
    pub inner: Arc<Mutex<HashMap<QueryId, QueryState>>>,
}

impl Default for RunningQueries {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::default())),
        }
    }
}

pub struct QueryHandle<'a> {
    query_id: QueryId,
    queries: &'a RunningQueries,
}

impl QueryHandle<'_> {
    pub fn set_state(&self, new_state: QueryState) -> Result<(), StateError> {
        let mut inner = self.queries.inner.lock().unwrap();
        let entry = inner.entry(self.query_id);
        match entry {
            Entry::Occupied(mut entry) => {
                entry.insert(QueryState::transition(entry.get(), new_state)?);
            }
            Entry::Vacant(entry) => {
                entry.insert(QueryState::transition(&QueryState::Empty, new_state)?);
            }
        }

        Ok(())
    }

    pub fn status(&self) -> Option<QueryStatus> {
        let inner = self.queries.inner.lock().unwrap();
        inner.get(&self.query_id).map(QueryStatus::from)
    }
}

impl RunningQueries {
    pub fn handle(&self, query_id: QueryId) -> QueryHandle {
        QueryHandle {
            query_id,
            queries: self,
        }
    }
}
