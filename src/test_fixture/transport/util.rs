use std::sync::Weak;
use crate::sync::Arc;
use crate::helpers::{HelperIdentity, SubscriptionType, Transport, TransportCommand, TransportError};
use crate::test_fixture::transport::InMemoryTransport;
use async_trait::async_trait;
use futures_util::SinkExt;

/// Transport that does not acknowledge send requests until the given number of send requests
/// is received. `wait` blocks the current task until this condition is satisfied.
#[derive(Clone)]
pub struct DelayedTransport<T> {
    inner: T,
    barrier: Arc<tokio::sync::Barrier>,
}

impl <T: Transport> DelayedTransport<T> {
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
impl <T: Transport> Transport for DelayedTransport<T> {
    type CommandStream = T::CommandStream;

    async fn subscribe(&self, subscription: SubscriptionType) -> Self::CommandStream {
        self.inner.subscribe(subscription).await
    }

    async fn send(&self, destination: &HelperIdentity, command: TransportCommand) -> Result<(), TransportError> {
        self.barrier.wait().await;
        self.inner.send(destination, command).await
    }
}

/// Transport that fails every `send` request using provided `error_fn` to resolve errors.
pub struct FailingTransport<F> {
    error_fn: F,
}

impl<F: Fn(TransportCommand) -> TransportError> FailingTransport<F> {
    pub fn new(error_fn: F) -> Self {
        Self { error_fn }
    }
}

#[async_trait]
impl<F: Fn(TransportCommand) -> TransportError + Send + Sync + 'static> Transport for FailingTransport<F> {
    type CommandStream = <Weak<InMemoryTransport> as Transport>::CommandStream;

    async fn subscribe(&self, subscription: SubscriptionType) -> Self::CommandStream {
        unimplemented!()
    }

    async fn send(&self, _destination: &HelperIdentity, command: TransportCommand) -> Result<(), TransportError> {
        Err((self.error_fn)(command))
    }
}
