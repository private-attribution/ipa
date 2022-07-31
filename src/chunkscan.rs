use crate::error::BoxError;
use futures::{ready, Stream};
use pin_project::pin_project;
use std::future::Future;
use std::mem;
use std::pin::Pin;
use std::task::{Context, Poll};
use tracing::error;

/// A variant of stream transform that combines semantic of `StreamExt::chunks` and `StreamExt::scan`.
/// Consumes the input stream and keeps accumulating items in the internal buffer until it reaches
/// `capacity` elements. Then the elements are moved to the `f` function that must produce a future
/// resolvable to the same type as element type of the input stream.
///
/// When elements are given to the `f` function, no other elements will be taken off the input stream
/// until the future returned by it is resolved. It is important to note that the resulting item
/// returned by this function is kept in the buffer, so next time stream is polled, only (`capacity`-1)
/// elements will be polled off before calling `f` again.
///
/// If input stream yields `None` while buf does not have at least `capacity` elements, `f` will
/// be called on partial buf
#[pin_project]
pub struct ChunkScan<St: Stream, F, Fut> {
    /// Input stream
    #[pin]
    stream: St,

    /// how many elements to keep in the buffer before calling `f`
    capacity: usize,

    /// Buffer for items taken off the input stream
    buf: Vec<St::Item>,

    /// Transforms Vec<Item> -> Future<Output=Result<Item, Error>>
    f: F,

    /// future in progress
    #[pin]
    future: Option<Fut>,
}

impl<St, F, Fut> Stream for ChunkScan<St, F, Fut>
where
    St: Stream,
    St::Item: Clone,
    F: FnMut(Vec<St::Item>) -> Fut,
    Fut: Future<Output = Result<St::Item, BoxError>>,
{
    type Item = St::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.as_mut().project();

        loop {
            // if future is set we poll it first before taking anything off the input stream
            if let Some(fut) = this.future.as_mut().as_pin_mut() {
                let item = ready!(fut.poll(cx));
                this.future.set(None);

                if let Err(e) = item {
                    // TODO (alex): we should propagate errors back to caller
                    error!({ e }, "An error occurred computing next stream element");
                    return Poll::Ready(None);
                }
                let item = item.unwrap();
                this.buf.push(item.clone());

                return Poll::Ready(Some(item));
            } else if let Some(item) = ready!(this.stream.as_mut().poll_next(cx)) {
                // otherwise we poll the input stream
                this.buf.push(item);
                if this.buf.len() == *this.capacity {
                    let items = mem::replace(this.buf, Vec::with_capacity(2));
                    this.future.set(Some((this.f)(items)));
                }
            } else if !this.buf.is_empty() {
                // Input stream is closed, but we still have some items to process
                let items = mem::take(this.buf);
                this.future.set(Some((this.f)(items)));
            } else {
                return Poll::Ready(None);
            }
        }
    }
}

impl<St, F, Fut> ChunkScan<St, F, Fut>
where
    St: Stream,
    F: FnMut(Vec<St::Item>) -> Fut,
    Fut: Future<Output = Result<St::Item, BoxError>>,
{
    pub fn new(stream: St, capacity: usize, f: F) -> Self {
        Self {
            stream,
            capacity,
            buf: Vec::with_capacity(capacity),
            f,
            future: None,
        }
    }
}
