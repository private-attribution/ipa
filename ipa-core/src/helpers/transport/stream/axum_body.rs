use std::{
    pin::Pin,
    task::{Context, Poll},
};

use axum::extract::{BodyStream, FromRequest, RequestParts};
use bytes::Bytes;
use futures::{Stream, TryStreamExt};
use hyper::Body;
use pin_project::pin_project;

use crate::error::BoxError;

type AxumInner = futures::stream::MapErr<BodyStream, fn(axum::Error) -> crate::error::BoxError>;

#[pin_project]
pub struct WrappedAxumBodyStream(#[pin] AxumInner);

impl WrappedAxumBodyStream {
    /// Wrap an axum body stream, returning an instance of `crate::helpers::BodyStream`.
    ///
    /// In the real-world-infra configuration, that is the same as a `WrappedAxumBodyStream`.
    #[cfg(feature = "real-world-infra")]
    #[must_use]
    pub fn new(inner: BodyStream) -> Self {
        Self::new_internal(inner)
    }

    pub(super) fn new_internal(inner: BodyStream) -> Self {
        Self(inner.map_err(axum::Error::into_inner as fn(axum::Error) -> BoxError))
    }

    #[must_use]
    pub fn empty() -> Self {
        Self::from_body(Bytes::new())
    }
}

impl Stream for WrappedAxumBodyStream {
    type Item = <AxumInner as Stream>::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().0.poll_next(cx)
    }
}

// Note that it is possible (although unlikely) that `from_body` panics.
#[cfg(any(test, feature = "test-fixture"))]
impl<Buf: Into<bytes::Bytes>> From<Buf> for WrappedAxumBodyStream {
    fn from(buf: Buf) -> Self {
        Self::from_body(buf.into())
    }
}

impl WrappedAxumBodyStream {
    /// # Panics
    /// If something goes wrong in axum or hyper constructing the request body stream,
    /// which probably can't happen here.
    pub fn from_body<T: Into<Body>>(body: T) -> Self {
        // The `FromRequest` trait defines `from_request` as async, but the implementation for
        // `BodyStream` never blocks, and it's not clear why it would need to, so it seems safe to
        // resolve the future with `now_or_never`.
        Self::new_internal(
            futures::FutureExt::now_or_never(BodyStream::from_request(&mut RequestParts::new(
                hyper::Request::builder()
                    .uri("/ignored")
                    .body(body.into())
                    .unwrap(),
            )))
            .unwrap()
            .unwrap(),
        )
    }
}

#[cfg(feature = "real-world-infra")]
#[async_trait::async_trait]
impl<B: hyper::body::HttpBody<Data = bytes::Bytes, Error = hyper::Error> + Send + 'static>
    FromRequest<B> for WrappedAxumBodyStream
{
    type Rejection = <BodyStream as FromRequest<B>>::Rejection;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        Ok(Self::new_internal(req.extract::<BodyStream>().await?))
    }
}
