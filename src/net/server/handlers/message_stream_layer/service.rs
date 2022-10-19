use super::future::ResponseFuture;
use axum::extract::RequestParts;
use axum::http::{Request, Response};
use std::task::{ready, Context, Poll};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;
use tower::Service;

/// `poll_ready` will first grab a permit via the `PollSender`. Once ready, the sender is injected
/// into the Request as an Extension. This can only be done once
#[derive(Debug)]
pub struct MessageStream<S, T> {
    inner: S,
    sender: Option<PollSender<T>>,
}

impl<S, T: Send + 'static> MessageStream<S, T> {
    pub fn new(inner: S, sender: mpsc::Sender<T>) -> Self {
        Self {
            inner,
            sender: Some(PollSender::new(sender)),
        }
    }
}

/// Within `poll_ready`, first grabs a permit for the [`PollSender`]. Then, pass the [`PollSender`]
/// into the request as an [`Extension`] on the `call`.
///
/// Leaves the [`Service`]'s `Error` type unspecified, so that it can be [`Infallible`] within the
/// context of Axum. That additionally means never returning an error, instead creating a response
/// with an error [`StatusCode`]
impl<S, ReqBody, ResBody, T> Service<Request<ReqBody>> for MessageStream<S, T>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ResBody: Default,
    T: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if ready!(self.sender.as_mut().unwrap().poll_reserve(cx)).is_ok() {
            self.inner.poll_ready(cx)
        } else {
            // if poll_reserve returns error, drop the sender since it is no longer usable
            // when `call` is called, will respond with error
            drop(self.sender.take());
            Poll::Ready(Ok(()))
        }
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        match self.sender.take() {
            // error in poll_ready, or `call` called more than once
            None => ResponseFuture::PollErr,
            Some(sender) => {
                let mut req_parts = RequestParts::new(req);
                req_parts.extensions_mut().insert(sender);
                let req = req_parts
                    .try_into_request()
                    .expect("body should not be used");
                ResponseFuture::Inner(self.inner.call(req))
            }
        }
    }
}

/// When cloning, the `PollSender` does not transfer any permits it has acquired.
/// Thus, `clone` is equivalent to initializing a new [`UpstreamMiddleware`] with the same `sender`
impl<S: Clone, T> Clone for MessageStream<S, T> {
    // manually implement Clone to get around requirements that `T` must be [`Clone`]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            sender: self.sender.clone(),
        }
    }
}
