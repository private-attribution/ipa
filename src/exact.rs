use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::stream::Stream;
use pin_project::pin_project;

/// An analogue of [`ExactSizeIterator`] for [`Stream`].
/// This behaves exactly as you might expect based on the documentation of
/// [`ExactSizeIterator`].
///
/// [`ExactSizeIterator`]: std::iter::ExactSizeIterator
/// [`Stream`]: futures::stream::Stream
pub trait ExactSizeStream: Stream {
    /// Return the length of the stream that remains.
    fn len(&self) -> usize {
        let (lower, upper) = self.size_hint();
        assert_eq!(upper, Some(lower));
        lower
    }

    /// Return whether there are values remaining in the stream.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<I> ExactSizeStream for futures::stream::Iter<I> where I: ExactSizeIterator {}
impl<T> ExactSizeStream for futures::stream::Empty<T> {}
impl<T> ExactSizeStream for futures::stream::Once<T> where T: futures::Future {}
impl<S> ExactSizeStream for Pin<Box<S>> where S: ExactSizeStream {}
impl<S> ExactSizeStream for futures::stream::Take<S> where S: Stream {}

#[pin_project]
pub struct FixedLength<S> {
    #[pin]
    inner: S,
    len: usize,
}

impl<S: Stream> FixedLength<S> {
    /// Create a new fixed-length stream.
    ///
    /// Note that this is safe on the same basis that `ExactSizeIterator` is safe in
    /// that code cannot rely on the claims of this type for ensuring safety of code.
    #[allow(dead_code)] // TODO - use in infra
    pub fn new(inner: S, len: usize) -> Self {
        Self { inner, len }
    }
}

impl<S: Stream> Stream for FixedLength<S> {
    type Item = S::Item;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        let res = this.inner.as_mut().poll_next(cx);
        if let Poll::Ready(v) = &res {
            if v.is_some() {
                *this.len = (*this.len).wrapping_sub(1);
            } else {
                // This can't be a real assertion because we are at the mercy of
                // remote inputs here; that error will be caught in other ways.
                // Note that wrapping is fine in this case.
                #[cfg_attr(debug_assertions, allow(clippy::cast_possible_wrap))]
                {
                    debug_assert_eq!(
                        *this.len, 0,
                        "FixedLength stream ended with {} remaining",
                        *this.len as isize
                    );
                }
            }
        }
        res
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len, Some(self.len))
    }
}

impl<S: Stream> ExactSizeStream for FixedLength<S> {}

#[cfg(all(test, unit_test))]
mod test {
    use futures::stream::iter;
    use futures_util::StreamExt;

    use crate::exact::{ExactSizeStream, FixedLength};

    #[test]
    fn fixed_stream() {
        const COUNT: usize = 7;
        let fixed = FixedLength::new(iter(0..COUNT), COUNT);
        assert_eq!(fixed.len(), COUNT);
    }

    #[tokio::test]
    async fn polling_works() {
        const COUNT: usize = 5;
        let mut fixed = FixedLength::new(iter(0..COUNT), COUNT);
        assert_eq!(fixed.len(), COUNT);
        assert_eq!(fixed.next().await, Some(0));
        assert_eq!(fixed.len(), COUNT - 1);
        assert_eq!(
            fixed.collect::<Vec<_>>().await,
            (1..COUNT).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn drain_correct() {
        const COUNT: usize = 4;
        let mut fixed = FixedLength::new(iter(0..COUNT), COUNT);
        assert_eq!(fixed.len(), COUNT);
        while fixed.next().await.is_some() {
            // noop
        }
        assert!(fixed.is_empty());
    }

    #[tokio::test]
    #[cfg_attr(
        debug_assertions,
        should_panic = "FixedLength stream ended with 1 remaining"
    )]
    async fn oversized() {
        const COUNT: usize = 6;
        let fixed = FixedLength::new(iter(0..COUNT), COUNT + 1);
        assert_eq!(fixed.len(), COUNT + 1);
        assert_eq!(
            fixed.collect::<Vec<_>>().await,
            (0..COUNT).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    #[cfg_attr(
        debug_assertions,
        should_panic = "FixedLength stream ended with -1 remaining"
    )]
    async fn undersized() {
        const COUNT: usize = 4;
        let fixed = FixedLength::new(iter(0..COUNT), COUNT - 1);
        assert_eq!(fixed.len(), COUNT - 1);
        assert_eq!(
            fixed.collect::<Vec<_>>().await,
            (0..COUNT).collect::<Vec<_>>()
        );
    }
}
