use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use pin_project::pin_project;

#[pin_project(project = MaybeFutureProj)]
pub enum MaybeFuture<Fut: Future> {
    Future(#[pin] Fut),
    Value(Option<Fut::Output>),
}

impl<Fut: Future> Future for MaybeFuture<Fut> {
    type Output = Fut::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            MaybeFutureProj::Future(fut) => fut.poll(cx),
            MaybeFutureProj::Value(val) => {
                Poll::Ready(val.take().expect("future polled again after completion"))
            }
        }
    }
}

impl<Fut: Future> MaybeFuture<Fut> {
    pub fn future(fut: Fut) -> Self {
        MaybeFuture::Future(fut)
    }

    pub fn value(val: Fut::Output) -> Self {
        MaybeFuture::Value(Some(val))
    }
}

impl<Fut: Future<Output = Result<(), E>>, E> MaybeFuture<Fut> {
    pub fn future_or_ok<F: FnOnce() -> Fut>(condition: bool, f: F) -> Self {
        if condition {
            MaybeFuture::Future(f())
        } else {
            MaybeFuture::Value(Some(Ok(())))
        }
    }
}
