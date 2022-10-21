use super::future::ResponseFuture;
use crate::net::server::MpcServerError;
use axum::http::{Request, Response};
use std::task::{ready, Context, Poll};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;
use tower::Service;

#[derive(Debug)]
pub enum SenderStatus<T> {
    NotReady(PollSender<T>),
    Ready(PollSender<T>),
    Err,
    Spent,
}

// manually implement Clone to get around requirements that `T` must be [`Clone`]
impl<T> Clone for SenderStatus<T> {
    fn clone(&self) -> Self {
        match self {
            Self::NotReady(sender) => Self::NotReady(sender.clone()),
            Self::Ready(sender) => Self::Ready(sender.clone()),
            Self::Err => Self::Err,
            Self::Spent => Self::Spent,
        }
    }
}

pub struct ReservedPermit<T>(PollSender<T>);
impl<T: Send + 'static> ReservedPermit<T> {
    pub fn send(&mut self, item: T) -> Result<(), MpcServerError> {
        Ok(self.0.send_item(item)?)
    }
}

/// `poll_ready` will first grab a permit via the `PollSender`. Once ready, the sender is injected
/// into the Request as an Extension. This can only be done once
#[derive(Debug)]
pub struct MessageStream<S, T> {
    inner: S,
    sender: SenderStatus<T>,
}

impl<S, T: Send + 'static> MessageStream<S, T> {
    pub fn new(inner: S, sender: mpsc::Sender<T>) -> Self {
        Self {
            inner,
            sender: SenderStatus::NotReady(PollSender::new(sender)),
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
        match &mut self.sender {
            SenderStatus::NotReady(sender) => {
                if ready!(sender.poll_reserve(cx)).is_ok() {
                    // swap `NotReady` for `Ready`
                    if let SenderStatus::NotReady(sender) =
                        std::mem::replace(&mut self.sender, SenderStatus::Spent)
                    {
                        self.sender = SenderStatus::Ready(sender);
                        self.inner.poll_ready(cx)
                    } else {
                        panic!("SenderStatus was not NotReady")
                    }
                } else {
                    // if `poll_reserve` returns error, forward error to response
                    self.sender = SenderStatus::Err;
                    Poll::Ready(Ok(()))
                }
            }
            SenderStatus::Ready(_) => self.inner.poll_ready(cx),
            SenderStatus::Err | SenderStatus::Spent => Poll::Ready(Ok(())),
        }
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        match &self.sender {
            SenderStatus::NotReady(_) => panic!("poll_ready not called"),
            SenderStatus::Ready(_) => {
                if let SenderStatus::Ready(sender) =
                    std::mem::replace(&mut self.sender, SenderStatus::Spent)
                {
                    // must insert value wrapped in `Some` due to `Extension`'s `FromRequest` impl
                    // calling `.clone()` on all `Extension`s. Thus, we must call `.extensions_mut` on
                    // the `Request` inside the handler, which does NOT call `.clone()`, but which means
                    // we must `.take()` the `sender` out of the `Extension` to prevent borrow contention
                    // on the `Request`.
                    req.extensions_mut().insert(Some(ReservedPermit(sender)));
                    ResponseFuture::Inner(self.inner.call(req))
                } else {
                    panic!("SenderStatus was not Ready")
                }
            }
            SenderStatus::Err => ResponseFuture::PollErr,
            SenderStatus::Spent => panic!("call already called"),
        }
    }
}

/// When cloning, the `PollSender` does not transfer any permits it has acquired.
/// Thus, `clone` is equivalent to initializing a new [`UpstreamMiddleware`] with the same `sender`
impl<S: Clone, T> Clone for MessageStream<S, T> {
    // manually implement Clone to get around requirements that `T` must be [`Clone`]
    fn clone(&self) -> Self {
        // Enforces that `.clone()` is never called after `.poll_ready()` has been called
        #[cfg(debug_assertions)]
        assert!(match self.sender {
            SenderStatus::NotReady(_) => true,
            SenderStatus::Ready(_) | SenderStatus::Err | SenderStatus::Spent => false,
        });

        Self {
            inner: self.inner.clone(),
            sender: self.sender.clone(),
        }
    }
}
