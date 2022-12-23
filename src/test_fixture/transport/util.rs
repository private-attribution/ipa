use crate::sync::Arc;
use crate::helpers::{HelperIdentity, SubscriptionType, Transport, TransportCommand, TransportError};
use crate::test_fixture::transport::InMemoryTransport;
use async_trait::async_trait;

/// Transport that does not acknowledge send requests until the given number of send requests
/// is received. `wait` blocks the current task until this condition is satisfied.
#[cfg(test)]
pub struct DelayedTransport {
    inner: InMemoryTransport,
    barrier: std::sync::Arc<tokio::sync::Barrier>,
}

#[cfg(test)]
impl DelayedTransport {
    #[must_use]
    pub fn new(inner: InMemoryTransport, concurrent_sends: usize) -> Self {
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
    type CommandStream = <Arc<InMemoryTransport> as Transport>::CommandStream;

    async fn subscribe(&self, subscription: SubscriptionType) -> Self::CommandStream {
        todo!()
    }

    async fn send(&self, destination: &HelperIdentity, command: TransportCommand) -> Result<(), TransportError> {
        todo!()
    }
    //
    // async fn send(&self, command: Command<'_>) -> Result<(), super::TransportError> {
    //     self.barrier.wait().await;
    //     self.inner.send(command).await
    // }
    //
    // fn app_layer(&self, ring: &RingConfiguration) -> Self::AppLayer {
    //     self.inner.app_layer(ring)
    // }
}

/// Transport that fails every `send` request using provided `error_fn` to resolve errors.
#[cfg(test)]
pub struct FailingTransport<F> {
    inner: InMemoryTransport,
    error_fn: F,
}

#[cfg(test)]
impl<F: Fn(TransportCommand) -> super::TransportError> FailingTransport<F> {
    pub fn new(inner: InMemoryTransport, error_fn: F) -> Self {
        Self { inner, error_fn }
    }
}

// #[cfg(test)]
// #[async_trait]
// impl<F: Fn(Command) -> super::TransportError + Sync> Transport for FailingTransport<F> {
//     type AppLayer = std::sync::Arc<InMemoryEndpoint>;
//
//     async fn send(&self, command: Command<'_>) -> Result<(), super::TransportError> {
//         Err((self.error_fn)(command))
//     }
//
//     fn app_layer(&self, ring: &RingConfiguration) -> Self::AppLayer {
//         self.inner.app_layer(ring)
//     }
// }
