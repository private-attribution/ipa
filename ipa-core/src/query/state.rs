use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::{Debug, Display, Formatter},
    future::Future,
    task::Poll,
};

use ::tokio::sync::oneshot::{error::TryRecvError, Receiver};
use futures::{ready, FutureExt};
use serde::{Deserialize, Serialize};

use crate::{
    executor::IpaJoinHandle,
    helpers::{query::QueryConfig, RoleAssignment},
    protocol::QueryId,
    query::runner::QueryResult,
    sync::Mutex,
};

/// The status of query processing
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
    /// Complete API has been called and is waiting for query to finish.
    AwaitingCompletion,
    /// Query has finished and results are available.
    Completed,
}

impl Display for QueryStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<&QueryState> for QueryStatus {
    fn from(source: &QueryState) -> Self {
        match source {
            QueryState::Empty => panic!("Query cannot be in the empty state"),
            QueryState::Preparing(_) => QueryStatus::Preparing,
            QueryState::AwaitingInputs(_, _) => QueryStatus::AwaitingInputs,
            QueryState::Running(_) => QueryStatus::Running,
            QueryState::AwaitingCompletion => QueryStatus::AwaitingCompletion,
            QueryState::Completed(_) => QueryStatus::Completed,
        }
    }
}

/// This function is used, among others, by the [`Processor`] to return a unified response when
/// queried about the state of a sharded helper. In such scenarios, there will be many different
/// [`QueryStatus`] and the [`Processor`] needs to return a single one that describes the entire
/// helper. With this function we're saying that the minimum state across all shards is the one
/// that describes the helper.
#[must_use]
pub fn min_status(a: QueryStatus, b: QueryStatus) -> QueryStatus {
    match (a, b) {
        (QueryStatus::Preparing, _) | (_, QueryStatus::Preparing) => QueryStatus::Preparing,
        (QueryStatus::AwaitingInputs, _) | (_, QueryStatus::AwaitingInputs) => {
            QueryStatus::AwaitingInputs
        }
        (QueryStatus::Running, _) | (_, QueryStatus::Running) => QueryStatus::Running,
        (QueryStatus::AwaitingCompletion, _) | (_, QueryStatus::AwaitingCompletion) => {
            QueryStatus::AwaitingCompletion
        }
        (QueryStatus::Completed, _) => QueryStatus::Completed,
    }
}

/// TODO: a macro would be very useful here to keep it in sync with `QueryStatus`
pub enum QueryState {
    Empty,
    Preparing(QueryConfig),
    AwaitingInputs(QueryConfig, RoleAssignment),
    Running(RunningQuery),
    AwaitingCompletion,
    Completed(QueryResult),
}

impl QueryState {
    pub fn transition(cur_state: &Self, new_state: Self) -> Result<Self, StateError> {
        use QueryState::{AwaitingInputs, Empty, Preparing, Running};

        match (cur_state, &new_state) {
            // If query is not running, coordinator initial state is preparing
            // and followers initial state is awaiting inputs
            (Empty, Preparing(_) | AwaitingInputs(_, _))
            | (Preparing(_), AwaitingInputs(_, _))
            | (AwaitingInputs(_, _), Running(_)) => Ok(new_state),
            (_, Preparing(_)) => Err(StateError::AlreadyRunning),
            (_, _) => Err(StateError::InvalidState {
                from: cur_state.into(),
                to: QueryStatus::from(&new_state),
            }),
        }
    }
}

pub struct RunningQuery {
    pub result: Receiver<QueryResult>,

    /// `JoinHandle` for the query task.
    ///
    /// The join handle is only useful for the purpose of aborting the query. Tasks started with
    /// `tokio::spawn` run to completion whether or not anything waits on the handle.
    ///
    /// We could return the result via the `JoinHandle`, except that we want to check the status
    /// of the task, and shuttle doesn't implement `JoinHandle::is_finished`.
    pub join_handle: IpaJoinHandle<()>,
}

impl RunningQuery {
    pub fn try_complete(&mut self) -> Option<QueryResult> {
        match self.result.try_recv() {
            Ok(result) => Some(result),
            Err(TryRecvError::Closed) => {
                panic!("query completed without returning a result");
            }
            Err(TryRecvError::Empty) => None,
        }
    }
}

impl Future for RunningQuery {
    type Output = QueryResult;

    #[allow(clippy::match_wild_err_arm)] // The error is a RecvError, which has no detail to report.
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match ready!(self.result.poll_unpin(cx)) {
            Ok(result) => Poll::Ready(result),
            Err(_) => {
                panic!("query completed without returning a result");
            }
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
    pub inner: Mutex<HashMap<QueryId, QueryState>>,
}

impl Default for RunningQueries {
    fn default() -> Self {
        Self {
            inner: Mutex::new(HashMap::default()),
        }
    }
}

impl Debug for RunningQueries {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "RunningQueries[{}]", self.inner.lock().unwrap().len())
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

    pub fn remove_query_on_drop(&self) -> RemoveQuery {
        RemoveQuery::new(self.query_id, self.queries)
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

/// RAII guard to clean up query state when dropped.
pub struct RemoveQuery<'a> {
    inner: Option<RemoveQueryInner<'a>>,
}

struct RemoveQueryInner<'a> {
    query_id: QueryId,
    queries: &'a RunningQueries,
}

impl<'a> RemoveQuery<'a> {
    pub fn new(query_id: QueryId, queries: &'a RunningQueries) -> Self {
        Self {
            inner: Some(RemoveQueryInner { query_id, queries }),
        }
    }

    pub fn restore(mut self) {
        self.inner.take().unwrap();
    }
}

impl Drop for RemoveQuery<'_> {
    fn drop(&mut self) {
        if let Some(inner) = &self.inner {
            if inner
                .queries
                .inner
                .lock()
                .unwrap()
                .remove_entry(&inner.query_id)
                .is_none()
            {
                tracing::warn!(
                    "{q} query is not registered, but attempted to terminate",
                    q = inner.query_id
                );
            }
        }
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use crate::query::{state::min_status, QueryStatus};

    #[test]
    fn test_order() {
        // this list sorted in priority order. Preparing is the lowest possible value,
        // while Completed is the highest.
        let all = [
            QueryStatus::Preparing,
            QueryStatus::AwaitingInputs,
            QueryStatus::Running,
            QueryStatus::AwaitingCompletion,
            QueryStatus::Completed,
        ];

        for i in 0..all.len() {
            let this = all[i];
            for other in all.into_iter().skip(i) {
                assert_eq!(this, min_status(this, other));
                assert_eq!(this, min_status(other, this));
            }
        }
    }
}
