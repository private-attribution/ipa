use super::MessageStream;
use tokio::sync::mpsc;
use tower::Layer;

/// Wraps a [`MessageStream`] so that it can be used in a [`Layer`]
#[allow(clippy::module_name_repetitions)] // following standard naming convention
pub struct MessageStreamLayer<T> {
    sender: mpsc::Sender<T>,
}

impl<T: Send + 'static> MessageStreamLayer<T> {
    pub fn new(sender: mpsc::Sender<T>) -> Self {
        Self { sender }
    }
}

impl<S, T: Send + 'static> Layer<S> for MessageStreamLayer<T> {
    type Service = MessageStream<S, T>;

    fn layer(&self, inner: S) -> Self::Service {
        MessageStream::new(inner, self.sender.clone())
    }
}
