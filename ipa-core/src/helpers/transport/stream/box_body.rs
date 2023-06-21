use crate::helpers::transport::stream::BoxBytesStream;

use futures::Stream;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

pub struct WrappedBoxBodyStream(BoxBytesStream);

impl WrappedBoxBodyStream {
    /// Wrap an axum body stream, returning an instance of `crate::helpers::BodyStream`.
    #[cfg(all(feature = "in-memory-infra", feature = "web-app"))]
    #[must_use]
    pub fn new(inner: axum::extract::BodyStream) -> Self {
        Self(Box::pin(super::WrappedAxumBodyStream::new_internal(inner)))
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
impl<B: hyper::body::HttpBody<Data = bytes::Bytes, Error = hyper::Error> + Send + 'static>
    axum::extract::FromRequest<B> for WrappedBoxBodyStream
{
    type Rejection = <axum::extract::BodyStream as axum::extract::FromRequest<B>>::Rejection;

    async fn from_request(
        req: &mut axum::extract::RequestParts<B>,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self::new(req.extract().await?))
    }
}
