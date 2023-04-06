use crate::helpers::transport::stream::{StreamCollection, StreamKey};
use futures::Stream;
use futures_util::StreamExt;
#[cfg(any(not(feature = "web-app"), feature = "test-fixture"))]
use std::convert::identity;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

/// Represents a stream of records.
/// If stream is not received yet, each poll generates a waker that is used internally to wake up
/// the task when stream is received.
/// Once stream is received, it is moved to this struct and it acts as a proxy to it.
pub struct ReceiveRecords<S, T = S, F = fn(T) -> S>
where
    F: FnOnce(T) -> S,
{
    inner: ReceiveRecordsInner<S, T, F>,
}

impl<S> ReceiveRecords<S, S, fn(S) -> S> {
    #[cfg(any(not(feature = "web-app"), feature = "test-fixture"))]
    pub(crate) fn new(key: StreamKey, coll: StreamCollection<S>) -> Self {
        Self {
            inner: ReceiveRecordsInner::Pending(key, coll, Some(identity)),
        }
    }
}

impl<S, T, F> ReceiveRecords<S, T, F>
where
    F: FnOnce(T) -> S,
{
    #[cfg(feature = "web-app")]
    pub(crate) fn mapped(key: StreamKey, coll: StreamCollection<T>, f: F) -> Self {
        Self {
            inner: ReceiveRecordsInner::Pending(key, coll, Some(f)),
        }
    }
}

impl<S, T, F> Stream for ReceiveRecords<S, T, F>
where
    S: Stream + Unpin,
    T: Stream + Unpin,
    F: (FnOnce(T) -> S) + Unpin,
{
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::get_mut(self).inner.poll_next_unpin(cx)
    }
}

/// Inner state for [`ReceiveRecords`] struct
enum ReceiveRecordsInner<S, T, F: FnOnce(T) -> S> {
    Pending(StreamKey, StreamCollection<T>, Option<F>),
    Ready(S),
}

impl<S: Stream, T, F> Stream for ReceiveRecordsInner<S, T, F>
where
    S: Stream + Unpin,
    T: Stream + Unpin,
    F: (FnOnce(T) -> S) + Unpin,
{
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = Pin::get_mut(self);
        loop {
            match this {
                Self::Pending(key, streams, map_fn) => {
                    if let Some(stream) = streams.add_waker(key, cx.waker()) {
                        // There may be a std::mem function that would allow
                        // doing this without using an Option for map_fn,
                        // but TBD if this mapped stream support is really needed.
                        *this = Self::Ready((map_fn.take().unwrap())(stream));
                    } else {
                        return Poll::Pending;
                    }
                }
                Self::Ready(stream) => return stream.poll_next_unpin(cx),
            }
        }
    }
}
