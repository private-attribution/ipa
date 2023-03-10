use std::io;
use crate::{
    sync::Arc,
};

use async_trait::async_trait;
use futures::Stream;
use crate::helpers::HelperIdentity;
use crate::helpers::transport::{ChannelledTransport, NoResourceIdentifier, QueryIdBinding, RouteId, RouteParams, StepBinding};
use crate::protocol::{QueryId, Step};

/// Transport that does not acknowledge send requests until the given number of send requests
/// is received. `wait` blocks the current task until this condition is satisfied.
#[derive(Clone)]
pub struct DelayedTransport<T> {
    inner: T,
    barrier: Arc<tokio::sync::Barrier>,
}

impl<T: ChannelledTransport> DelayedTransport<T> {
    #[must_use]
    pub fn new(inner: T, concurrent_sends: usize) -> Self {
        Self {
            inner,
            barrier: Arc::new(tokio::sync::Barrier::new(concurrent_sends)),
        }
    }

    pub async fn wait(&self) {
        self.barrier.wait().await;
    }
}

#[async_trait]
impl<T: ChannelledTransport> ChannelledTransport for DelayedTransport<T> {
    type RecordsStream = T::RecordsStream;

    fn identity(&self) -> HelperIdentity {
        self.inner.identity()
    }

    async fn send<D, Q, S, R>(&self, dest: HelperIdentity, route: R, data: D) -> Result<(), io::Error> where Option<QueryId>: From<Q>, Option<Step>: From<S>, Q: QueryIdBinding, S: StepBinding, R: RouteParams<RouteId, Q, S>, D: Stream<Item=Vec<u8>> + Send + 'static {
        self.barrier.wait().await;
        self.inner.send(dest, route, data).await
    }

    fn receive<R: RouteParams<NoResourceIdentifier, QueryId, Step>>(&self, from: HelperIdentity, route: R) -> Self::RecordsStream {
        self.inner.receive(from, route)
    }
}
