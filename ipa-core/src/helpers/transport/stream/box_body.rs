use std::{
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(all(feature = "in-memory-infra", feature = "web-app"))]
use axum::RequestExt;
use bytes::Bytes;
use futures::{stream::StreamExt, Stream};

use crate::helpers::{transport::stream::BoxBytesStream, BytesStream};

pub struct WrappedBoxBodyStream(BoxBytesStream);

impl WrappedBoxBodyStream {
    /// Wrap an axum body stream, returning an instance of `crate::helpers::BodyStream`.
    #[cfg(all(feature = "in-memory-infra", feature = "web-app"))]
    #[must_use]
    pub fn new(inner: axum::extract::BodyStream) -> Self {
        Self(Box::pin(super::WrappedAxumBodyStream::new_internal(inner)))
    }

    pub fn from_infallible<S: Stream<Item = Box<[u8]>> + Send + 'static>(input: S) -> Self {
        Self(Box::pin(input.map(Bytes::from).map(Ok)))
    }

    pub fn from_bytes_stream<S: BytesStream + 'static>(input: S) -> Self {
        Self(Box::pin(input))
    }

    #[must_use]
    pub fn empty() -> Self {
        WrappedBoxBodyStream(Box::pin(futures::stream::empty()))
    }
}

impl Stream for WrappedBoxBodyStream {
    type Item = <BoxBytesStream as Stream>::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let p = self.0.as_mut();
        p.poll_next(cx)
    }
}

#[cfg(any(test, feature = "test-fixture"))]
impl<Buf: Into<bytes::Bytes>> From<Buf> for WrappedBoxBodyStream {
    fn from(buf: Buf) -> Self {
        Self(Box::pin(futures::stream::once(futures::future::ready(Ok(
            buf.into(),
        )))))
    }
}

#[cfg(all(feature = "in-memory-infra", feature = "web-app"))]
#[async_trait::async_trait]
impl<
        S: Send + Sync,
        B: hyper::body::HttpBody<Data = bytes::Bytes, Error = hyper::Error> + Send + 'static,
    > axum::extract::FromRequest<S, B> for WrappedBoxBodyStream
{
    type Rejection = <axum::extract::BodyStream as axum::extract::FromRequest<S, B>>::Rejection;

    async fn from_request(req: hyper::Request<B>, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::new(req.extract().await?))
    }
}
