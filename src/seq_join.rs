use futures::{stream::TryCollect, Future, Stream, TryStreamExt};
use pin_project::pin_project;
use std::{
    collections::VecDeque,
    future::IntoFuture,
    iter::Fuse,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};

/// This helper function might be necessary to convince the compiler that
/// the return value from [`seq_try_join_all`] implements `Send`.
/// Use this if you get higher-ranked lifetime errors that mention `std::marker::Send`.
pub fn assert_send<'a, O>(
    fut: impl Future<Output = O> + Send + 'a,
) -> impl Future<Output = O> + Send + 'a {
    fut
}

/// Sequentially join futures from an iterator.
///
/// This function polls futures in strict sequence.
/// If any future blocks, up to `active - 1` futures after it will be polled so
/// that they make progress.
///
/// Unlike [`StreamExt::buffered`], Futures from the stream must resolve in the
/// same order in which they are produced.
///
/// # Panics
///
/// If a future produced from the stream resolves ahead of a preceding future.
/// To help ensure that earlier futures resolve first, this guarantees that
/// earlier futures are always polled before later futures.
///
/// # Deadlocks
///
/// This will fail to resolve if the progress of any future depends on a future more
/// than `active` items behind it in the input sequence.
///
/// [`try_join_all`]: futures::future::try_join_all
/// [`Stream`]: futures::stream::Stream
/// [`StreamExt::buffered`]: futures::stream::StreamExt::buffered
pub fn seq_join<I, F, O>(active: NonZeroUsize, iter: I) -> SequentialFutures<I::IntoIter, F>
where
    I: IntoIterator<Item = F>,
    I::IntoIter: Send,
    F: Future<Output = O>,
{
    // TODO: Take a Stream instance instead of an IntoIterator so that we can chain these,
    // which might help reduce the amount of state we hold in between operations.
    SequentialFutures {
        iter: iter.into_iter().fuse(),
        active: VecDeque::with_capacity(active.get()),
    }
}

/// The `SeqJoin` trait wraps `seq_try_join_all`, providing the `active` parameter
/// from the provided context so that the value can be made consistent.
pub trait SeqJoin {
    /// Perform a sequential join of the futures from the provided iterable.
    /// This uses [`seq_join`], with the current state of the associated object
    /// being used to determine the number of active items to track (see [`active_work`]).
    ///
    /// A rough rule of thumb for how to decide between this and [`parallel_join`] is
    /// that this should be used whenever you are iterating over different records.
    /// [`parallel_join`] is better suited to smaller batches, such as iterating over
    /// the bits of a value for a single record.
    ///
    /// Note that the join functions from the [`futures`] crate, such as [`join3`],
    /// are also parallel and can be used where you have a small, fixed number of tasks.
    ///
    /// Be especially careful if you use the random bits generator with this.
    /// The random bits generator can produce values out of sequence.
    /// You might need to use [`parallel_join`] for that.
    ///
    /// [`active_work`]: Self::active_work
    /// [`parallel_join`]: Self::parallel_join
    /// [`join3`]: futures::future::join3
    fn try_join<I, F, O, E>(&self, iterable: I) -> TryCollect<SeqTryJoinAll<I, F>, Vec<O>>
    where
        I: IntoIterator<Item = F> + Send,
        I::IntoIter: Send,
        F: Future<Output = Result<O, E>>,
    {
        seq_try_join_all(self.active_work(), iterable)
    }

    /// Join multiple tasks in parallel.  Only do this if you can't use a sequential join.
    fn parallel_join<I>(&self, iterable: I) -> futures::future::TryJoinAll<I::Item>
    where
        I: IntoIterator,
        I::Item: futures::future::TryFuture,
    {
        #[allow(clippy::disallowed_methods)] // Just in this one place.
        futures::future::try_join_all(iterable)
    }

    /// The amount of active work that is concurrently permitted.
    fn active_work(&self) -> NonZeroUsize;
}

type SeqTryJoinAll<I, F> = SequentialFutures<<I as IntoIterator>::IntoIter, F>;

/// A substitute for [`futures::future::try_join_all`] that uses [`seq_join`].
/// This awaits all the provided futures in order,
/// aborting early if any future returns `Result::Err`.
pub fn seq_try_join_all<I, F, O, E>(
    active: NonZeroUsize,
    iterable: I,
) -> TryCollect<SeqTryJoinAll<I, F>, Vec<O>>
where
    I: IntoIterator<Item = F> + Send,
    I::IntoIter: Send,
    F: Future<Output = Result<O, E>>,
{
    seq_join(active, iterable).try_collect()
}

#[pin_project]
pub struct SequentialFutures<I, F>
where
    I: Iterator<Item = F> + Send,
    F: IntoFuture,
{
    iter: Fuse<I>,
    active: VecDeque<Pin<Box<F::IntoFuture>>>,
}

impl<I, F> Stream for SequentialFutures<I, F>
where
    I: Iterator<Item = F> + Send,
    F: IntoFuture,
{
    type Item = F::Output;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        // Draw more values from the input, up to the capacity.
        while this.active.len() < this.active.capacity() {
            if let Some(f) = this.iter.next() {
                this.active.push_back(Box::pin(f.into_future()));
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
                    assert!(res.is_pending(), "future resolved out of order");
                }
                Poll::Pending
            }
        } else {
            assert!(this.iter.next().is_none());
            Poll::Ready(None)
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let in_progress = self.active.len();
        let (lower, upper) = self.iter.size_hint();
        (
            lower.saturating_add(in_progress),
            upper.and_then(|u| u.checked_add(in_progress)),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::seq_join::{seq_join, seq_try_join_all};
    use futures::{
        future::{lazy, pending, BoxFuture},
        Future, StreamExt,
    };
    use std::{convert::Infallible, iter::once, num::NonZeroUsize};

    async fn immediate(count: u32) {
        let capacity = NonZeroUsize::new(3).unwrap();
        let values = seq_join(capacity, (0..count).map(|i| async move { i }))
            .collect::<Vec<_>>()
            .await;
        assert_eq!((0..count).collect::<Vec<_>>(), values);
    }

    #[tokio::test]
    async fn within_capacity() {
        immediate(2).await;
        immediate(1).await;
    }

    #[tokio::test]
    async fn over_capacity() {
        immediate(10).await;
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

    #[tokio::test]
    async fn join_success() {
        fn fut<T>(v: T) -> impl Future<Output = T>
        where
            T: Send,
        {
            lazy(move |_| v)
        }

        let active = NonZeroUsize::new(10).unwrap();
        let res = seq_try_join_all(
            active,
            [fut::<Result<_, Infallible>>(Ok(1)), fut(Ok(2)), fut(Ok(3))],
        )
        .await
        .unwrap();
        assert_eq!(vec![1, 2, 3], res);
    }

    #[tokio::test]
    async fn try_join_early_abort() {
        const ERROR: &str = "error message";
        fn f(i: u32) -> impl Future<Output = Result<u32, &'static str>> {
            lazy(move |_| match i {
                1 => Ok(1),
                2 => Err(ERROR),
                _ => panic!("should have aborted earlier"),
            })
        }

        let active = NonZeroUsize::new(10).unwrap();
        let err = seq_try_join_all(active, [f(1), f(2), f(3)])
            .await
            .unwrap_err();
        assert_eq!(err, ERROR);
    }
}
