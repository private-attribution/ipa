use futures::{ready, Stream};
use pin_project::pin_project;

use std::ops::Add;

use std::pin::Pin;
use std::task::{Context, Poll};

/// implementation of how `incrementer_adder` works
/// holds the stream being consumed, and a stateful incrementer that increases with every item
#[pin_project]
pub struct IncrementerAdder<St: Stream> {
    #[pin]
    stream: St,
    inc: St::Item,
}

impl<St: Stream> IncrementerAdder<St> {
    /// initialize with the default zero value of the item being incremented
    pub fn new(stream: St) -> Self
    where
        St::Item: Default,
    {
        Self {
            stream,
            inc: St::Item::default(),
        }
    }
}

/// types get complicated here.
/// given some base stream `St: Stream`, that has an `Item` that can be incremented (as evidenced by
/// `From<u8>`) and added to itself (as evidenced by `Add<St::Item, Output = St::Item>`), create a
/// new stream that takes the base stream, and add the value being incremented for each item.
///
/// e.g.
/// input stream: \[0, 0, 0, 0, 0\]
/// output stream: \[1, 2, 3, 4, 5\]
///
/// This is not very ergonomic, and requires a deep understanding of types, as well as [Pin] and
/// `pin_project`. The tradeoff is we can transform streams in a custom way; the primary benefit
/// of a custom transform is that it can be stateful, as seen here with an incrementer.
impl<St: Stream> Stream for IncrementerAdder<St>
where
    St::Item: From<u8> + for<'a> Add<&'a St::Item, Output = St::Item>,
{
    type Item = St::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        let res = ready!(this.stream.as_mut().poll_next(cx));
        let one: St::Item = 1u8.into();
        *this.inc = one + this.inc;
        Poll::Ready(res.map(|i| i + this.inc))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.stream.size_hint()
    }
}
