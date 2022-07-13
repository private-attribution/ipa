use futures::{ready, Stream};
use pin_project::pin_project;
use std::future::Future;
use std::ops::AddAssign;
use std::pin::Pin;
use std::task::{Context, Poll};

/// implementation of how `sum` works
/// holds the stream being consumed, and a stateful incrementer of the sum
#[pin_project]
pub struct Sum<St: Stream> {
    #[pin]
    stream: St,
    summation: St::Item,
}

impl<St: Stream> Sum<St> {
    /// initializes with the default value of item being summed
    pub fn new(stream: St) -> Self
    where
        St::Item: Default,
    {
        Sum {
            stream,
            summation: St::Item::default(),
        }
    }
}

/// In this case, implement a [`Future`], not a [`Stream`], as it produces a single output. Still
/// consumes a stream to produce that output.
///
/// Given some base `St: Stream` that has `Item` that can be added (as evidenced by
/// `AddAssign<St::Item>` and `Clone`d (in order to return the value after summation), wait for the
/// base stream to be exhausted, then emit the single value `summation`.
///
/// Interestingly, it relies on the `stream`'s `poll_next` function to return a `Poll::Pending` (via
/// the `ready!` macro), and otherwise iterates through the `stream` synchronously.
impl<St: Stream> Future for Sum<St>
where
    St::Item: Clone + AddAssign<St::Item>,
{
    type Output = St::Item;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        loop {
            match ready!(this.stream.as_mut().poll_next(cx)) {
                Some(n) => *this.summation += n,
                None => return Poll::Ready(this.summation.clone()),
            }
        }
    }
}
