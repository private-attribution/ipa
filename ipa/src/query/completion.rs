use std::future::Future;

use std::{
    pin::Pin,
    task::{ready, Context, Poll},
};

use crate::{
    error::Error,
    query::{runner::QueryResult, state::RemoveQuery},
    task::JoinHandle,
};

use pin_project::pin_project;

/// Query completion polls the tokio task to get the results and cleans up the query state after.
#[pin_project]
pub struct Handle<'a> {
    query_state_guard: RemoveQuery<'a>,
    #[pin]
    inner: JoinHandle<QueryResult>,
}

impl<'a> Future for Handle<'a> {
    type Output = QueryResult;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match ready!(this.inner.poll(cx)) {
            Ok(results) => Poll::Ready(results),
            Err(e) => {
                tracing::error!("query task error: {e:?}");
                Poll::Ready(Err(Error::RuntimeError(e)))
            }
        }
    }
}

impl<'a> Handle<'a> {
    pub fn new(guard: RemoveQuery<'a>, inner: JoinHandle<QueryResult>) -> Self {
        Self {
            query_state_guard: guard,
            inner,
        }
    }
}
