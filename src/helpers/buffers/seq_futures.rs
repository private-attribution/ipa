use futures::{Future, Stream};
use pin_project::pin_project;
use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};

#[pin_project]
struct SequentialFutures<I, Fut, O>
where
    I: Iterator<Item = Fut>,
    Fut: Future<Output = O>,
{
    input: I,
    active: VecDeque<Pin<Box<Fut>>>,
}

impl<I, Fut, O> Stream for SequentialFutures<I, Fut, O>
where
    I: Iterator<Item = Fut>,
    Fut: Future<Output = O>,
{
    type Item = O;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        // Draw more values from the input, up to the capacity.
        while this.active.len() < this.active.capacity() {
            if let Some(f) = this.input.next() {
                this.active.push_back(Box::pin(f));
            } else {
                break;
            }
        }

        if let Some(f) = this.active.front_mut() {
            if let Poll::Ready(v) = Future::poll(Pin::as_mut(f), cx) {
                drop(this.active.pop_front());
                Poll::Ready(Some(v))
            } else {
                for f in this.active.iter_mut().skip(1) {
                    let res = Future::poll(Pin::as_mut(f), cx);
                    assert!(!res.is_ready(), "future resolved out of order");
                }
                Poll::Pending
            }
        } else {
            Poll::Ready(None)
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let in_progress = self.active.len();
        let (lower, upper) = self.input.size_hint();
        (
            lower.saturating_add(in_progress),
            upper.and_then(|u| u.checked_add(in_progress)),
        )
    }
}

/// Sequentially join futures from an iterator.
///
/// This function polls futures sequentially.  If any future blocks, up to `active - 1`
/// futures after it will be polled so that they make progress.  Futures must resolve in
/// the same order in which they are provided by the iterator/stream.  
///
/// # Deadlocks
///
/// This will fail to resolve if the progress of any future depends on a future more
/// than `active` items behind it in the input sequence.
fn seq_join<I, It, Fut, O>(active: NonZeroUsize, input: I) -> SequentialFutures<It, Fut, O>
where
    I: IntoIterator<Item = Fut, IntoIter = It>,
    It: Iterator<Item = Fut>,
    Fut: Future<Output = O>,
{
    SequentialFutures {
        input: input.into_iter(),
        active: VecDeque::with_capacity(active.get()),
    }
}

#[cfg(test)]
mod test {
    use crate::helpers::buffers::seq_futures::seq_join;
    use futures::{
        future::{pending, BoxFuture},
        StreamExt,
    };
    use std::{iter::once, num::NonZeroUsize};

    async fn range(max: u32) {
        let capacity = NonZeroUsize::new(3).unwrap();
        let values = seq_join(capacity, (0..max).map(|i| async move { i }))
            .collect::<Vec<_>>()
            .await;
        assert_eq!((0..max).collect::<Vec<_>>(), values);
    }

    #[tokio::test]
    async fn within_capacity() {
        range(2).await;
        range(1).await;
    }

    #[tokio::test]
    async fn over_capacity() {
        range(10).await;
    }

    #[tokio::test]
    #[should_panic(expected = "future resolved out of order")]
    async fn out_of_order() {
        let capacity = NonZeroUsize::new(3).unwrap();
        let unresolved: BoxFuture<'_, u32> = Box::pin(pending());
        let it = once(unresolved)
            .chain((0..3_u32).map(|i| -> BoxFuture<'_, u32> { Box::pin(async move { i }) }));
        drop(seq_join(capacity, it).collect::<Vec<_>>().await);
    }
}
