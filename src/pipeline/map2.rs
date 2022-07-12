use futures::{ready, Stream};
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// implementation of how `map2` works
/// holds the stream that is being mapped, and the method used to map
/// example of how to recreate familiar behavior
#[pin_project]
pub struct Map2<St, F> {
    #[pin]
    stream: St,
    f: F,
}

impl<St, F> Map2<St, F> {
    pub fn new(stream: St, f: F) -> Self {
        Self { stream, f }
    }
}

/// types get complicated here.
/// given some base stream `St: Stream`, and some function `F: St::Item -> T`, create a new stream
/// `<Map2 as Stream>::<Item = T>` where function `F` is applied to all elements of `St`.
///
/// This is not very ergonomic, and requires a deep understanding of types, as well as [`Pin`] and
/// `pin_project`. The tradeoff is we can transform streams in a custom way; the primary benefit
/// of a custom transform is that it can be stateful, as seen in [`IncrementerAdder`]
impl<St: Stream, T, F: FnMut(St::Item) -> T> Stream for Map2<St, F> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        let res = ready!(this.stream.as_mut().poll_next(cx));
        Poll::Ready(res.map(this.f))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.stream.size_hint()
    }
}
