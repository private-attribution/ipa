use std::{
    pin::{Pin, pin},
    task::{Context, Poll},
};

use futures::Stream;
use futures_util::StreamExt;
use pin_project::pin_project;
use tracing::error;

use crate::{
    error::BoxError,
    helpers::{
        TransportIdentity,
        transport::stream::{StreamCollection, StreamKey},
    },
};

/// Adapt a stream of `Result<T: Into<Vec<u8>>, Error>` to a stream of `Vec<u8>`.
///
/// If an error is encountered, the error is logged, and the stream is terminated.
pub struct LogErrors<S, T, E>
where
    S: Stream<Item = Result<T, E>> + Unpin,
    T: Into<Vec<u8>>,
    E: Into<BoxError>,
{
    inner: S,
}

impl<S, T, E> LogErrors<S, T, E>
where
    S: Stream<Item = Result<T, E>> + Unpin,
    T: Into<Vec<u8>>,
    E: Into<BoxError>,
{
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, T, E> Stream for LogErrors<S, T, E>
where
    S: Stream<Item = Result<T, E>> + Unpin,
    T: Into<Vec<u8>>,
    E: Into<BoxError>,
{
    type Item = Vec<u8>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::get_mut(self).inner.poll_next_unpin(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Some(chunk.into())),
            Poll::Ready(Some(Err(err))) => {
                // Report this error in the server log since it may require investigation
                // by the helper party operators. It will not be informative for a report
                // collector.
                //
                // Note that returning `Poll::Ready(None)` here will be turned back into
                // an `EndOfStream` error by `UnorderedReceiver`.
                error!("error reading records: {}", err.into());
                Poll::Ready(None)
            }
            Poll::Ready(None) => Poll::Ready(None),
        }
    }
}

/// Represents a stream of records.
/// If stream is not received yet, each poll generates a waker that is used internally to wake up
/// the task when stream is received.
/// Once stream is received, it is moved to this struct and it acts as a proxy to it.
#[pin_project]
pub struct ReceiveRecords<I, S> {
    #[pin]
    inner: ReceiveRecordsInner<I, S>,
}

impl<I, S> ReceiveRecords<I, S> {
    pub(crate) fn new(key: StreamKey<I>, coll: StreamCollection<I, S>) -> Self {
        Self {
            inner: ReceiveRecordsInner::Pending(key, coll),
        }
    }
}

#[cfg(all(test, descriptive_gate, any(unit_test, web_test)))]
impl<I: TransportIdentity, S: crate::helpers::BytesStream> ReceiveRecords<I, S> {
    /// Converts this into a stream that yields owned byte chunks.
    ///
    /// ## Panics
    /// If inner stream yields [`Err`] chunk.
    pub(crate) fn into_bytes_stream(self) -> impl Stream<Item = Vec<u8>> {
        self.inner.map(Result::unwrap).map(Into::into)
    }
}

impl<I: TransportIdentity, S: Stream> Stream for ReceiveRecords<I, S> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().inner.poll_next(cx)
    }
}

/// Inner state for [`ReceiveRecords`] struct
#[pin_project(project = ReceiveRecordsInnerProj)]
enum ReceiveRecordsInner<I, S> {
    Pending(StreamKey<I>, StreamCollection<I, S>),
    Ready(#[pin] S),
}

impl<I: TransportIdentity, S: Stream> Stream for ReceiveRecordsInner<I, S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.as_mut().project() {
                ReceiveRecordsInnerProj::Pending(key, streams) => {
                    if let Some(stream) = streams.add_waker(key, cx.waker()) {
                        self.set(Self::Ready(stream));
                    } else {
                        return Poll::Pending;
                    }
                }
                ReceiveRecordsInnerProj::Ready(stream) => return stream.poll_next(cx),
            }
        }
    }
}
