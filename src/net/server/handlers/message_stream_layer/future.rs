use axum::response::Response;
use hyper::StatusCode;
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

/// Either forwards the results from the inner Future, or responds with error encountered
#[allow(clippy::module_name_repetitions)] // following standard naming convention
#[pin_project(project = ProjResp)]
pub enum ResponseFuture<F> {
    Inner(#[pin] F),
    PollErr,
}

impl<F, B, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<Response<B>, E>>,
    B: Default,
{
    type Output = Result<Response<B>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            ProjResp::Inner(f) => Poll::Ready(Ok(ready!(f.poll(cx))?)),
            ProjResp::PollErr => {
                let mut res = Response::new(B::default());
                *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                Poll::Ready(Ok(res))
            }
        }
    }
}
