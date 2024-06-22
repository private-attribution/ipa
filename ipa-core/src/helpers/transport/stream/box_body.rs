use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{stream::StreamExt, Stream};
use futures_util::stream;

use crate::helpers::{transport::stream::BoxBytesStream, BytesStream};

pub struct WrappedBoxBodyStream(BoxBytesStream);

impl WrappedBoxBodyStream {
    /// Wrap an axum body stream, returning an instance of `crate::helpers::BodyStream`.
    #[cfg(all(feature = "in-memory-infra", feature = "web-app"))]
    #[must_use]
    pub fn new(bytes: bytes::Bytes) -> Self {
        let stream = futures::stream::once(futures::future::ready(Ok(bytes)));
        Self::from_bytes_stream(stream)
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

    pub fn from_byte_vec(buf: Vec<u8>) -> Self {
        const MAX_CHUNK_SIZE: usize = 1 << 16; // 64 KiB
        let mut segment = Bytes::from(buf);
        let mut segments = Vec::with_capacity(segment.len() / MAX_CHUNK_SIZE);
        while segment.len() > MAX_CHUNK_SIZE {
            segments.push(Ok(segment.split_to(MAX_CHUNK_SIZE)));
        }
        segments.push(Ok(segment));

        tracing::info!("[in-memory-infra] created body with {} chunks, each does not exceed {} size", segments.len(), MAX_CHUNK_SIZE);
        Self::from_bytes_stream(stream::iter(segments))
        // Self::new(Body::from_stream(stream::iter(segments)))
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
impl<S> axum::extract::FromRequest<S> for WrappedBoxBodyStream
where
    S: Send + Sync,
{
    type Rejection = crate::net::Error;

    async fn from_request(
        req: axum::extract::Request,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Bytes::from_request(req, _state)
            .await
            .map(Self::new)
            .map_err(crate::net::Error::InvalidBytesBody)
    }
}
