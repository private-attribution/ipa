mod aligned;

pub use aligned::ByteArrStream as AlignedByteArrStream;

use crate::error::BoxError;
use axum::extract::BodyStream;
use futures::Stream;
use futures_util::{
    stream::{self, BoxStream},
    TryStreamExt,
};
use hyper::body::Bytes;
use std::pin::Pin;
use std::task::{Context, Poll};

/// represents the item of an underlying stream
type Item = Result<Bytes, BoxError>;

pub struct ByteArrStream {
    stream: BoxStream<'static, Item>,
}

impl ByteArrStream {
    #[must_use]
    pub fn new(stream: BoxStream<'static, Item>) -> Self {
        Self { stream }
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)] // `size_in_bytes` known to be small
    pub fn align(self, size_in_bytes: usize) -> AlignedByteArrStream {
        AlignedByteArrStream::new(self.stream, size_in_bytes)
    }
}

impl From<BodyStream> for ByteArrStream {
    fn from(stream: BodyStream) -> Self {
        ByteArrStream::new(Box::pin(stream.map_err(<BoxError>::from)) as BoxStream<'static, Item>)
    }
}

impl From<Vec<u8>> for ByteArrStream {
    fn from(vec: Vec<u8>) -> Self {
        ByteArrStream::new(Box::pin(stream::iter(std::iter::once(Ok(Bytes::from(
            vec,
        ))))))
    }
}

#[cfg(test)]
impl ByteArrStream {
    /// converts the entire stream into a vec; only intended for use in tests
    /// # Panics
    /// if the stream has any failure
    pub async fn to_vec(self) -> Vec<u8> {
        self.try_collect::<Vec<_>>()
            .await
            .unwrap()
            .into_iter()
            .flat_map(|bytes| bytes.to_vec())
            .collect()
    }
}

impl Stream for ByteArrStream {
    type Item = Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.stream.as_mut().poll_next(cx)
    }
}
