use crate::helpers::messaging::Gateway;

use crate::protocol::QueryId;

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
    /// Helpers are negotiating the shared secrets to create PRSS and other things
    Negotiating,
    /// Query is being executed and can be interrupted by request.
    Running,
    /// Query processing has finished and the status of processing is available.
    /// TODO: completion status and TTL
    Completed,
}

impl From<&QueryState> for QueryStatus {
    fn from(source: &QueryState) -> Self {
        match source {
            QueryState::Preparing => QueryStatus::Preparing,
            QueryState::AwaitingInputs(_) => QueryStatus::AwaitingInputs,
        }
    }
}

/// TODO: a macro would be very useful here to keep it in sync with `QueryStatus`
pub enum QueryState {
    Preparing,
    AwaitingInputs(Gateway),
}

impl QueryState {
    pub fn transition(cur_state: Option<&Self>, new_state: Self) -> Result<Self, StateError> {
        match (cur_state, &new_state) {
            (None, QueryState::Preparing)
            | (Some(QueryState::Preparing), QueryState::AwaitingInputs(_)) => Ok(new_state),
            (Some(_), QueryState::Preparing) => Err(StateError::AlreadyRunning),
            (_, _) => Err(StateError::InvalidState {
                from: cur_state.map(Into::into),
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
    InvalidState {
        from: Option<QueryStatus>,
        to: QueryStatus,
    },
}

/// Keeps track of queries running on this helper.
pub struct RunningQueries {
    inner: Arc<Mutex<HashMap<QueryId, QueryState>>>,
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
                entry.insert(QueryState::transition(Some(entry.get()), new_state)?);
            }
            Entry::Vacant(entry) => {
                entry.insert(QueryState::transition(None, new_state)?);
            }
        }

        Ok(())
    }
}

impl RunningQueries {
    pub fn handle(&self, query_id: QueryId) -> QueryHandle {
        QueryHandle {
            query_id,
            queries: self,
        }
    }

    pub fn get_status(&self, query_id: QueryId) -> Option<QueryStatus> {
        self.inner.lock().unwrap().get(&query_id).map(Into::into)
    }
}
