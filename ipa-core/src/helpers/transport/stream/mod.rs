#[cfg(feature = "web-app")]
mod axum_body;
mod box_body;
#[allow(dead_code)]
mod buffered;
mod collection;
mod input;

use std::{
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(feature = "web-app")]
pub use axum_body::WrappedAxumBodyStream;
pub use box_body::WrappedBoxBodyStream;
use bytes::Bytes;
pub use collection::{StreamCollection, StreamKey};
use futures::{stream::iter, Stream};
use futures_util::StreamExt;
use generic_array::GenericArray;
pub use input::{LengthDelimitedStream, RecordsStream, SingleRecordStream};

use crate::{const_assert, error::BoxError, ff::Serializable};

pub trait BytesStream: Stream<Item = Result<Bytes, BoxError>> + Send {
    /// Collects the entire stream into a vec; only intended for use in tests
    /// # Panics
    /// if the stream has any failure
    #[cfg(test)]
    fn to_vec(self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<u8>> + Send>>
    where
        Self: Sized + 'static,
    {
        use futures::StreamExt;

        Box::pin(self.map(|item| item.unwrap().to_vec()).concat())
    }
}

impl<S: Stream<Item = Result<Bytes, BoxError>> + Send> BytesStream for S {}

pub type BoxBytesStream = Pin<Box<dyn BytesStream>>;

// This type alias serves a few purposes:
//  * Providing a type for input record streams when building without the `web-app` feature.
//    `WrappedBoxBodyStream` is a `Pin<Box<dyn BytesStream>>`.
//  * Reducing the number of places we depend on axum types.
//  * Avoiding an extra level of boxing in the production configuration using axum, since
//    the axum body stream type is already a `Pin<Box<dyn HttpBody>>`.
#[cfg(feature = "in-memory-infra")]
type BodyStreamInner = WrappedBoxBodyStream;
#[cfg(feature = "real-world-infra")]
type BodyStreamInner = WrappedAxumBodyStream;

/// Wrapper around [`BodyStreamInner`] that enforces checks relevant to both in-memory and
/// real-world implementations.
pub struct BodyStream {
    inner: BodyStreamInner,
}

impl BodyStream {
    /// Wrap a [`Bytes`] object, returning an instance of `crate::helpers::BodyStream`.
    /// If the given byte chunk exceeds [`super::MAX_HTTP_CHUNK_SIZE`],
    /// it will be split into multiple parts, each not exceeding that size.
    /// See #ipa/1141
    pub fn new(bytes: Bytes) -> Self {
        let stream = iter(bytes.split().into_iter().map(Ok::<_, BoxError>));
        Self::from_bytes_stream(stream)
    }

    #[must_use]
    pub fn empty() -> Self {
        Self {
            inner: BodyStreamInner::empty(),
        }
    }

    pub fn from_bytes_stream(stream: impl BytesStream + 'static) -> Self {
        Self {
            inner: BodyStreamInner::from_bytes_stream(stream),
        }
    }

    pub fn from_serializable_iter<I: IntoIterator<Item: Serializable, IntoIter: Send + 'static>>(
        input: I,
    ) -> Self {
        let stream = iter(input.into_iter().map(|item| {
            let mut buf = GenericArray::default();
            item.serialize(&mut buf);
            let bytes = Bytes::copy_from_slice(buf.as_slice());
            Ok::<_, BoxError>(bytes)
        }));

        Self {
            inner: BodyStreamInner::from_bytes_stream(stream),
        }
    }
}

impl Stream for BodyStream {
    type Item = Result<Bytes, BoxError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let next = self.inner.poll_next_unpin(cx);
        if let Poll::Ready(Some(Ok(v))) = &next {
            debug_assert!(
                v.len() <= MAX_HTTP_CHUNK_SIZE_BYTES,
                "Chunk size {} is greater than maximum allowed {MAX_HTTP_CHUNK_SIZE_BYTES} bytes",
                v.len()
            );
        };

        next
    }
}

impl From<Vec<u8>> for BodyStream {
    fn from(value: Vec<u8>) -> Self {
        Self::new(Bytes::from(value))
    }
}

#[cfg(feature = "web-app")]
#[async_trait::async_trait]
impl<S> axum::extract::FromRequest<S> for BodyStream
where
    S: Send + Sync,
{
    type Rejection = crate::net::Error;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self {
            inner: BodyStreamInner::from_request(req, state).await?,
        })
    }
}

/// The size is chosen somewhat arbitrary - feel free to change it, but don't go above 2Gb as
/// that will cause Hyper's HTTP2 to fail.
const MAX_HTTP_CHUNK_SIZE_BYTES: usize = 1024 * 1024; // 1MB
const_assert!(MAX_HTTP_CHUNK_SIZE_BYTES > 0 && MAX_HTTP_CHUNK_SIZE_BYTES < (1 << 31) - 1);

/// Trait for objects that can be split into multiple parts.
///
/// This trait is used to split the body of an HTTP request into multiple parts
/// when the request body is too large to fit in memory. This can happen if the
/// request body is being streamed from a file or other large source.
trait Split {
    type Dest;

    fn split(self) -> Self::Dest;
}

impl Split for Bytes {
    type Dest = Vec<Self>;

    fn split(self) -> Self::Dest {
        tracing::trace!(
            "Will split '{sz}' bytes buffer into {chunks} chunks of size {MAX_HTTP_CHUNK_SIZE_BYTES}",
            sz = self.len(),
            chunks = self.len() / MAX_HTTP_CHUNK_SIZE_BYTES,
        );

        let mut segments = Vec::with_capacity(self.len() / MAX_HTTP_CHUNK_SIZE_BYTES);
        let mut segment = self;
        while segment.len() > MAX_HTTP_CHUNK_SIZE_BYTES {
            segments.push(segment.split_to(MAX_HTTP_CHUNK_SIZE_BYTES));
        }
        segments.push(segment);

        segments
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use bytes::Bytes;
    use futures::{future, stream, stream::TryStreamExt};

    use crate::{
        helpers::{transport::stream::MAX_HTTP_CHUNK_SIZE_BYTES, BodyStream},
        test_executor::run,
    };

    #[test]
    fn chunks_the_input() {
        run(|| async {
            let data = vec![0_u8; 2 * MAX_HTTP_CHUNK_SIZE_BYTES + 1];
            let stream = BodyStream::new(data.into());
            let chunks = stream.try_collect::<Vec<_>>().await.unwrap();

            assert_eq!(3, chunks.len());
            assert_eq!(MAX_HTTP_CHUNK_SIZE_BYTES, chunks[0].len());
            assert_eq!(MAX_HTTP_CHUNK_SIZE_BYTES, chunks[1].len());
            assert_eq!(1, chunks[2].len());
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "Chunk size 1048577 is greater than maximum allowed 1048576 bytes")]
    fn rejects_large_chunks() {
        run(|| async {
            let data = vec![0_u8; MAX_HTTP_CHUNK_SIZE_BYTES + 1];
            let stream =
                BodyStream::from_bytes_stream(stream::once(future::ready(Ok(Bytes::from(data)))));

            stream.try_collect::<Vec<_>>().await.unwrap();
        });
    }
}
