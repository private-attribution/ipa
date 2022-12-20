use crate::error::BoxError;
use crate::helpers::commands::RingConfiguration;
use crate::helpers::network::Network;
use crate::helpers::{Command, HelperIdentity};
#[cfg(test)]
use crate::test_fixture::network::{InMemoryEndpoint, InMemoryNetwork};
use async_trait::async_trait;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Command has been rejected by {identity:?}")]
    CommandRejected {
        identity: HelperIdentity,
        inner: BoxError,
    },
}

#[async_trait]
pub trait Transport {
    type AppLayer: Network;

    async fn send(&self, command: Command<'_>) -> Result<(), Error>;

    /// TODO: remove, it is not transport's job to create this.
    fn app_layer(&self, ring: &RingConfiguration) -> Self::AppLayer;
}

#[cfg(test)]
pub struct StubTransport {
    network: std::sync::Arc<InMemoryNetwork>,
}

#[cfg(test)]
#[async_trait]
impl Transport for StubTransport {
    type AppLayer = std::sync::Arc<InMemoryEndpoint>;

    async fn send(&self, _command: Command<'_>) -> Result<(), super::TransportError> {
        Ok(())
    }

    fn app_layer(&self, _ring: &RingConfiguration) -> Self::AppLayer {
        // TODO: right now it does not matter which endpoint it returns,
        // but it will matter soon.
        std::sync::Arc::clone(&self.network.endpoints[0])
    }
}

#[cfg(test)]
impl From<std::sync::Arc<InMemoryNetwork>> for StubTransport {
    fn from(network: std::sync::Arc<InMemoryNetwork>) -> Self {
        Self { network }
    }
}

/// Transport that does not acknowledge send requests until the given number of send requests
/// is received. `wait` blocks the current task until this condition is satisfied.
#[cfg(test)]
pub struct DelayedTransport {
    inner: StubTransport,
    barrier: std::sync::Arc<tokio::sync::Barrier>,
}

#[cfg(test)]
impl DelayedTransport {
    #[must_use]
    pub fn new(inner: StubTransport, concurrent_sends: usize) -> Self {
        Self {
            inner,
            barrier: std::sync::Arc::new(tokio::sync::Barrier::new(concurrent_sends)),
        }
    }

    pub async fn wait(&self) {
        self.barrier.wait().await;
    }
}

#[cfg(test)]
#[async_trait]
impl Transport for DelayedTransport {
    type AppLayer = <StubTransport as Transport>::AppLayer;

    async fn send(&self, command: Command<'_>) -> Result<(), super::TransportError> {
        self.barrier.wait().await;
        self.inner.send(command).await
    }

    fn app_layer(&self, ring: &RingConfiguration) -> Self::AppLayer {
        self.inner.app_layer(ring)
    }
}

/// Transport that fails every `send` request using provided `error_fn` to resolve errors.
#[cfg(test)]
pub struct FailingTransport<F> {
    inner: StubTransport,
    error_fn: F,
}

#[cfg(test)]
impl<F: Fn(Command) -> super::TransportError> FailingTransport<F> {
    pub fn new(inner: StubTransport, error_fn: F) -> Self {
        Self { inner, error_fn }
    }
}

#[cfg(test)]
#[async_trait]
impl<F: Fn(Command) -> super::TransportError + Sync> Transport for FailingTransport<F> {
    type AppLayer = std::sync::Arc<InMemoryEndpoint>;

    async fn send(&self, command: Command<'_>) -> Result<(), super::TransportError> {
        Err((self.error_fn)(command))
    }

    fn app_layer(&self, ring: &RingConfiguration) -> Self::AppLayer {
        self.inner.app_layer(ring)
    }
}
