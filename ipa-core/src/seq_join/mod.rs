use std::{future::IntoFuture, num::NonZeroUsize};

use futures::{
    Future, Stream, TryStreamExt,
    stream::{Iter as StreamIter, TryCollect, iter},
};

use crate::helpers::stream::ExactSizeStream;

#[cfg(not(feature = "multi-threading"))]
mod local;
#[cfg(feature = "multi-threading")]
mod multi_thread;

/// This helper function might be necessary to convince the compiler that
/// the return value from [`seq_try_join_all`] implements `Send`.
/// Use this if you get higher-ranked lifetime errors that mention `std::marker::Send`.
///
/// <https://github.com/rust-lang/rust/issues/102211#issuecomment-1367900125>
#[allow(dead_code)] // we would need it soon
pub fn assert_send<'a, O>(
    fut: impl Future<Output = O> + Send + 'a,
) -> impl Future<Output = O> + Send + 'a {
    fut
}

/// Sequentially join futures from a stream.
///
/// This function polls futures in strict sequence.
/// If any future blocks, up to `active - 1` futures after it will be polled so
/// that they make progress.
///
/// # Deadlocks
///
/// This will fail to resolve if the progress of any future depends on a future more
/// than `active` items behind it in the input sequence.
///
/// # Safety
/// If multi-threading is enabled, forgetting the resulting future will cause use-after-free error. Do not leak it or
/// prevent the future destructor from running.
///
/// [`try_join_all`]: futures::future::try_join_all
/// [`Stream`]: futures::stream::Stream
/// [`StreamExt::buffered`]: futures::stream::StreamExt::buffered
pub fn seq_join<'st, S, F, O>(active: NonZeroUsize, source: S) -> SequentialFutures<'st, S, F>
where
    S: Stream<Item = F> + Send + 'st,
    F: Future<Output = O> + Send,
    O: Send + 'static,
{
    #[cfg(feature = "multi-threading")]
    unsafe {
        SequentialFutures::new(active, source)
    }
    #[cfg(not(feature = "multi-threading"))]
    SequentialFutures::new(active, source)
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
    fn try_join<'fut, I, F, O, E>(
        &self,
        iterable: I,
    ) -> TryCollect<SeqTryJoinAll<'fut, I, F>, Vec<O>>
    where
        I: IntoIterator<Item = F> + Send,
        I::IntoIter: Send + 'fut,
        F: Future<Output = Result<O, E>> + Send + 'fut,
        O: Send + 'static,
        E: Send + 'static,
    {
        seq_try_join_all(self.active_work(), iterable)
    }

    /// Join multiple tasks in parallel.  Only do this if you can't use a sequential join.
    ///
    /// # Safety
    /// Forgetting the future returned from this function will cause use-after-free. This is a tradeoff between
    /// performance and safety that allows us to use regular references instead of Arc pointers.
    ///
    /// Dropping the future is always safe.
    #[cfg(feature = "multi-threading")]
    fn parallel_join<'a, I, F, O, E>(
        &self,
        iterable: I,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Vec<O>, E>> + Send + 'a>>
    where
        I: IntoIterator<Item = F> + Send,
        F: Future<Output = Result<O, E>> + Send + 'a,
        O: Send + 'static,
        E: Send + 'static,
    {
        unsafe { Box::pin(multi_thread::parallel_join(iterable)) }
    }

    /// Join multiple tasks in parallel.  Only do this if you can't use a sequential join.
    #[cfg(not(feature = "multi-threading"))]
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

type SeqTryJoinAll<'st, I, F> =
    SequentialFutures<'st, StreamIter<<I as IntoIterator>::IntoIter>, F>;

/// A substitute for [`futures::future::try_join_all`] that uses [`seq_join`].
/// This awaits all the provided futures in order,
/// aborting early if any future returns `Result::Err`.
pub fn seq_try_join_all<'iter, I, F, O, E>(
    active: NonZeroUsize,
    source: I,
) -> TryCollect<SeqTryJoinAll<'iter, I, F>, Vec<O>>
where
    I: IntoIterator<Item = F> + Send,
    I::IntoIter: Send + 'iter,
    F: Future<Output = Result<O, E>> + Send + 'iter,
    O: Send + 'static,
    E: Send + 'static,
{
    seq_join(active, iter(source)).try_collect()
}

impl<'fut, S, F> ExactSizeStream for SequentialFutures<'fut, S, F>
where
    S: Stream<Item = F> + Send + ExactSizeStream,
    F: IntoFuture,
    <F as IntoFuture>::IntoFuture: Send + 'fut,
    <<F as IntoFuture>::IntoFuture as Future>::Output: Send + 'static,
{
}

#[cfg(not(feature = "multi-threading"))]
pub use local::SequentialFutures;
#[cfg(feature = "multi-threading")]
pub use multi_thread::SequentialFutures;

#[cfg(all(test, any(unit_test, feature = "shuttle")))]
mod test {
    use std::{convert::Infallible, iter::once, num::NonZeroUsize, task::Poll};

    use futures::{
        Future, Stream, StreamExt,
        future::{BoxFuture, lazy},
        stream::{iter, poll_immediate},
    };

    use crate::{
        seq_join::{seq_join, seq_try_join_all},
        test_executor::run,
    };

    async fn immediate(count: u32) {
        let capacity = NonZeroUsize::new(3).unwrap();
        let values = seq_join(capacity, iter((0..count).map(|i| async move { i })))
            .collect::<Vec<_>>()
            .await;
        assert_eq!((0..count).collect::<Vec<_>>(), values);
    }

    #[test]
    fn within_capacity() {
        run(|| async {
            immediate(2).await;
            immediate(1).await;
        });
    }

    #[test]
    fn over_capacity() {
        run(|| async {
            immediate(10).await;
        });
    }

    #[test]
    fn size() {
        run(|| async {
            let mut count = 10_usize;
            let capacity = NonZeroUsize::new(3).unwrap();
            let mut values = seq_join(capacity, iter((0..count).map(|i| async move { i })));
            assert_eq!((count, Some(count)), values.size_hint());

            while values.next().await.is_some() {
                count -= 1;
                assert_eq!((count, Some(count)), values.size_hint());
            }
        });
    }

    #[test]
    fn out_of_order() {
        run(|| async {
            let capacity = NonZeroUsize::new(3).unwrap();
            let barrier = tokio::sync::Barrier::new(2);
            let unresolved: BoxFuture<'_, u32> = Box::pin(async {
                barrier.wait().await;
                0
            });
            let it = once(unresolved)
                .chain((1..4_u32).map(|i| -> BoxFuture<'_, u32> { Box::pin(async move { i }) }));
            let mut seq_futures = seq_join(capacity, iter(it));

            assert_eq!(
                Some(Poll::Pending),
                poll_immediate(&mut seq_futures).next().await
            );
            barrier.wait().await;
            assert_eq!(vec![0, 1, 2, 3], seq_futures.collect::<Vec<_>>().await);
        });
    }

    #[test]
    fn join_success() {
        fn f<T: Send>(v: T) -> impl Future<Output = Result<T, Infallible>> {
            lazy(move |_| Ok(v))
        }

        run(|| async {
            let active = NonZeroUsize::new(10).unwrap();
            let res = seq_try_join_all(active, (1..5).map(f)).await.unwrap();
            assert_eq!((1..5).collect::<Vec<_>>(), res);
        });
    }

    #[test]
    #[cfg_attr(
        all(feature = "shuttle", feature = "multi-threading"),
        should_panic(expected = "cancelled")
    )]
    fn does_not_block_on_error() {
        const ERROR: &str = "returning early is safe";
        use std::pin::Pin;

        fn f(i: u32) -> Pin<Box<dyn Future<Output = Result<u32, &'static str>> + Send>> {
            match i {
                1 => Box::pin(lazy(move |_| Ok(1))),
                2 => Box::pin(lazy(move |_| Err(ERROR))),
                _ => Box::pin(futures::future::pending()),
            }
        }

        run(|| async {
            let active = NonZeroUsize::new(10).unwrap();
            let err = seq_try_join_all(active, (1..=3).map(f)).await.unwrap_err();
            assert_eq!(err, ERROR);
        });
    }
}
