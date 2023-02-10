use crate::helpers::{
    HelperIdentity, SubscriptionType, Transport, TransportCommand, TransportError,
};
use crate::sync::Arc;

use async_trait::async_trait;

/// Transport that does not acknowledge send requests until the given number of send requests
/// is received. `wait` blocks the current task until this condition is satisfied.
#[derive(Clone)]
pub struct DelayedTransport<T> {
    inner: T,
    barrier: Arc<tokio::sync::Barrier>,
}

impl<T: Transport> DelayedTransport<T> {
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
impl<T: Transport> Transport for DelayedTransport<T> {
    type CommandStream = T::CommandStream;

    fn identity(&self) -> HelperIdentity {
        T::identity(&self.inner)
    }

    async fn subscribe(&self, subscription: SubscriptionType) -> Self::CommandStream {
        self.inner.subscribe(subscription).await
    }

    async fn send<C: Send + Into<TransportCommand>>(
        &self,
        destination: HelperIdentity,
        command: C,
    ) -> Result<(), TransportError> {
        self.barrier.wait().await;
        self.inner.send(destination, command).await
    }
}

/// Transport that fails every `send` request using provided `error_fn` to resolve errors.
#[derive(Clone)]
pub struct FailingTransport<T, F> {
    inner: T,
    error_fn: F,
}

impl<T: Transport, F: Fn(TransportCommand) -> TransportError> FailingTransport<T, F> {
    pub fn new(inner: T, error_fn: F) -> Self {
        Self { inner, error_fn }
    }
}

#[async_trait]
impl<T: Transport, F: Fn(TransportCommand) -> TransportError + Send + Sync + 'static> Transport
    for FailingTransport<T, F>
{
    type CommandStream = T::CommandStream;

    fn identity(&self) -> HelperIdentity {
        self.inner.identity()
    }

    async fn subscribe(&self, subscription: SubscriptionType) -> Self::CommandStream {
        self.inner.subscribe(subscription).await
    }

    async fn send<C: Send + Into<TransportCommand>>(
        &self,
        _destination: HelperIdentity,
        command: C,
    ) -> Result<(), TransportError> {
        Err((self.error_fn)(command.into()))
    }
}
