use std::{
    future::IntoFuture,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{
    stream::{iter, Iter as StreamIter, TryCollect},
    Future, Stream, StreamExt, TryStreamExt,
};
use pin_project::pin_project;

use crate::exact::ExactSizeStream;

/// This helper function might be necessary to convince the compiler that
/// the return value from [`seq_try_join_all`] implements `Send`.
/// Use this if you get higher-ranked lifetime errors that mention `std::marker::Send`.
///
/// <https://github.com/rust-lang/rust/issues/102211#issuecomment-1367900125>
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
    ) -> Pin<Box<dyn Future<Output = Result<Vec<O>, E>> + Send + 'a>>
    where
        I: IntoIterator<Item = F> + Send,
        F: Future<Output = Result<O, E>> + Send + 'a,
        O: Send + 'static,
        E: Send + 'static,
    {
        unsafe { multi_thread::parallel_join(iterable) }
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

#[cfg(feature = "multi-threading")]
pub type SequentialFutures<'fut, S, F> = multi_thread::SequentialFutures<'fut, S, F>;

#[cfg(not(feature = "multi-threading"))]
pub type SequentialFutures<'unused, S, F> = local::SequentialFutures<'unused, S, F>;

/// Parallel and sequential join that use at most one thread. Good for unit testing and debugging,
/// to get results in predictable order with fewer things happening at the same time.
#[cfg(not(feature = "multi-threading"))]
mod local {
    use std::{collections::VecDeque, marker::PhantomData};

    use super::*;

    enum ActiveItem<F: IntoFuture> {
        Pending(Pin<Box<F::IntoFuture>>),
        Resolved(F::Output),
    }

    impl<F: IntoFuture> ActiveItem<F> {
        /// Drives this item to resolved state when value is ready to be taken out. Has no effect
        /// if the value is ready.
        ///
        /// ## Panics
        /// Panics if this item is completed
        fn check_ready(&mut self, cx: &mut Context<'_>) -> bool {
            let ActiveItem::Pending(f) = self else {
                return true;
            };
            if let Poll::Ready(v) = Future::poll(Pin::as_mut(f), cx) {
                *self = ActiveItem::Resolved(v);
                true
            } else {
                false
            }
        }

        /// Takes the resolved value out
        ///
        /// ## Panics
        /// If the value is not ready yet.
        #[must_use]
        fn take(self) -> F::Output {
            let ActiveItem::Resolved(v) = self else {
                panic!("No value to take out");
            };

            v
        }
    }

    #[pin_project]
    pub struct SequentialFutures<'unused, S, F>
    where
        S: Stream<Item = F> + Send,
        F: IntoFuture,
    {
        #[pin]
        source: futures::stream::Fuse<S>,
        active: VecDeque<ActiveItem<F>>,
        _marker: PhantomData<fn(&'unused ()) -> &'unused ()>,
    }

    impl<S, F> SequentialFutures<'_, S, F>
    where
        S: Stream<Item = F> + Send,
        F: IntoFuture,
    {
        pub fn new(active: NonZeroUsize, source: S) -> Self {
            Self {
                source: source.fuse(),
                active: VecDeque::with_capacity(active.get()),
                _marker: PhantomData,
            }
        }
    }

    impl<S, F> Stream for SequentialFutures<'_, S, F>
    where
        S: Stream<Item = F> + Send,
        F: IntoFuture,
    {
        type Item = F::Output;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let mut this = self.project();

            // Draw more values from the input, up to the capacity.
            while this.active.len() < this.active.capacity() {
                if let Poll::Ready(Some(f)) = this.source.as_mut().poll_next(cx) {
                    this.active
                        .push_back(ActiveItem::Pending(Box::pin(f.into_future())));
                } else {
                    break;
                }
            }

            if let Some(item) = this.active.front_mut() {
                if item.check_ready(cx) {
                    let v = this.active.pop_front().map(ActiveItem::take);
                    Poll::Ready(v)
                } else {
                    for f in this.active.iter_mut().skip(1) {
                        f.check_ready(cx);
                    }
                    Poll::Pending
                }
            } else if this.source.is_done() {
                Poll::Ready(None)
            } else {
                Poll::Pending
            }
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let in_progress = self.active.len();
            let (lower, upper) = self.source.size_hint();
            (
                lower.saturating_add(in_progress),
                upper.and_then(|u| u.checked_add(in_progress)),
            )
        }
    }
}

/// Both joins use executor tasks to drive futures to completion. Much faster than single-threaded
/// version, so this is what we want to use in release/prod mode.
#[cfg(feature = "multi-threading")]
mod multi_thread {
    use futures::future::BoxFuture;
    use tracing::{Instrument, Span};

    use super::*;

    #[cfg(feature = "shuttle")]
    mod shuttle_spawner {
        use shuttle_crate::{
            future,
            future::{JoinError, JoinHandle},
        };

        use super::*;

        /// Spawner implementation for Shuttle framework to run tests in parallel
        pub(super) struct ShuttleSpawner;

        unsafe impl<T> async_scoped::spawner::Spawner<T> for ShuttleSpawner
        where
            T: Send + 'static,
        {
            type FutureOutput = Result<T, JoinError>;
            type SpawnHandle = JoinHandle<T>;

            fn spawn<F: Future<Output = T> + Send + 'static>(&self, f: F) -> Self::SpawnHandle {
                future::spawn(f)
            }
        }

        unsafe impl async_scoped::spawner::Blocker for ShuttleSpawner {
            fn block_on<T, F: Future<Output = T>>(&self, f: F) -> T {
                future::block_on(f)
            }
        }
    }

    #[cfg(feature = "shuttle")]
    type Spawner<'fut, T> = async_scoped::Scope<'fut, T, shuttle_spawner::ShuttleSpawner>;
    #[cfg(not(feature = "shuttle"))]
    type Spawner<'fut, T> = async_scoped::TokioScope<'fut, T>;

    unsafe fn create_spawner<'fut, T: Send + 'static>() -> Spawner<'fut, T> {
        #[cfg(feature = "shuttle")]
        return async_scoped::Scope::create(shuttle_spawner::ShuttleSpawner);
        #[cfg(not(feature = "shuttle"))]
        return async_scoped::TokioScope::create(async_scoped::spawner::use_tokio::Tokio);
    }

    #[pin_project]
    #[must_use = "Futures do nothing, unless polled"]
    pub struct SequentialFutures<'fut, S, F>
    where
        S: Stream<Item = F> + Send + 'fut,
        F: IntoFuture,
        <<F as IntoFuture>::IntoFuture as Future>::Output: Send + 'static,
    {
        #[pin]
        spawner: Spawner<'fut, F::Output>,
        #[pin]
        source: futures::stream::Fuse<S>,
        capacity: usize,
    }

    impl<S, F> SequentialFutures<'_, S, F>
    where
        S: Stream<Item = F> + Send,
        F: IntoFuture,
        <<F as IntoFuture>::IntoFuture as Future>::Output: Send + 'static,
    {
        pub unsafe fn new(active: NonZeroUsize, source: S) -> Self {
            SequentialFutures {
                spawner: unsafe { create_spawner() },
                source: source.fuse(),
                capacity: active.get(),
            }
        }
    }

    impl<'fut, S, F> Stream for SequentialFutures<'fut, S, F>
    where
        S: Stream<Item = F> + Send,
        F: IntoFuture,
        <F as IntoFuture>::IntoFuture: Send + 'fut,
        <<F as IntoFuture>::IntoFuture as Future>::Output: Send + 'static,
    {
        type Item = F::Output;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let mut this = self.project();

            // Draw more values from the input, up to the capacity.
            while this.spawner.remaining() < *this.capacity {
                if let Poll::Ready(Some(f)) = this.source.as_mut().poll_next(cx) {
                    // Making futures cancellable is critical to avoid hangs.
                    // if one of them panics, unwinding causes spawner to drop and, in turn,
                    // it blocks the thread to await all pending futures completion. If there is
                    // a dependency between futures, pending one will never complete.
                    // Cancellable futures will be cancelled when spawner is dropped which is
                    // the behavior we want.
                    this.spawner
                        .spawn_cancellable(f.into_future().instrument(Span::current()), || {
                            panic!("cancelled")
                        });
                } else {
                    break;
                }
            }

            // Poll spawner if it has work to do. If both source and spawner are empty, we're done
            if this.spawner.remaining() > 0 {
                this.spawner.as_mut().poll_next(cx).map(|v| match v {
                    Some(Ok(v)) => Some(v),
                    Some(Err(_)) => panic!("task is cancelled"),
                    None => None,
                })
            } else if this.source.is_done() {
                Poll::Ready(None)
            } else {
                Poll::Pending
            }
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let in_progress = self.spawner.remaining();
            let (lower, upper) = self.source.size_hint();
            (
                lower.saturating_add(in_progress),
                upper.and_then(|u| u.checked_add(in_progress)),
            )
        }
    }

    /// TODO: change it to impl Future once https://github.com/rust-lang/rust/pull/115822 is
    /// available in stable Rust.
    pub(super) unsafe fn parallel_join<'fut, I, F, O, E>(
        iterable: I,
    ) -> BoxFuture<'fut, Result<Vec<O>, E>>
    where
        I: IntoIterator<Item = F> + Send,
        F: Future<Output = Result<O, E>> + Send + 'fut,
        O: Send + 'static,
        E: Send + 'static,
    {
        let mut scope = {
            let iter = iterable.into_iter();
            let mut scope = unsafe { create_spawner() };
            for element in iter {
                // it is important to make those cancellable to avoid deadlocks if one of the spawned future panics.
                // If there is a dependency between futures, pending one will never complete.
                // Cancellable futures will be cancelled when spawner is dropped which is the behavior we want.
                scope.spawn_cancellable(element.instrument(Span::current()), || {
                    panic!("Future is cancelled.")
                });
            }
            scope
        };

        Box::pin(async move {
            let mut result = Vec::with_capacity(scope.len());
            while let Some(item) = scope.next().await {
                // join error is nothing we can do about
                result.push(item.unwrap()?)
            }
            Ok(result)
        })
    }
}

#[cfg(all(test, unit_test, not(feature = "multi-threading")))]
mod local_test {
    use std::{
        num::NonZeroUsize,
        ptr::null,
        sync::{Arc, Mutex},
        task::{Context, Poll, Waker},
    };

    use futures::{
        future::lazy,
        stream::{poll_fn, repeat_with},
        StreamExt,
    };

    use super::*;

    fn fake_waker() -> Waker {
        use std::task::{RawWaker, RawWakerVTable};
        const fn fake_raw_waker() -> RawWaker {
            const TABLE: RawWakerVTable =
                RawWakerVTable::new(|_| fake_raw_waker(), |_| {}, |_| {}, |_| {});
            RawWaker::new(null(), &TABLE)
        }
        unsafe { Waker::from_raw(fake_raw_waker()) }
    }

    /// Check the value of a counter, then reset it.
    fn assert_count(counter_r: &Arc<Mutex<usize>>, expected: usize) {
        let mut counter = counter_r.lock().unwrap();
        assert_eq!(*counter, expected);
        *counter = 0;
    }

    /// A fully synchronous test.
    #[test]
    fn synchronous() {
        let capacity = NonZeroUsize::new(3).unwrap();
        let v_r: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
        let v_w = Arc::clone(&v_r);
        // Track when the stream was polled,
        let polled_w: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let polled_r = Arc::clone(&polled_w);
        // when the stream produced something, and
        let produced_w: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let produced_r = Arc::clone(&produced_w);
        // when the future was read.
        let read_w: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let read_r = Arc::clone(&read_w);

        let stream = poll_fn(|_cx| {
            *polled_w.lock().unwrap() += 1;
            if let Some(v) = v_r.lock().unwrap().take() {
                *produced_w.lock().unwrap() += 1;
                let read_w = Arc::clone(&read_w);
                Poll::Ready(Some(lazy(move |_| {
                    *read_w.lock().unwrap() += 1;
                    v
                })))
            } else {
                // Note: we can ignore `cx` because we are driving this directly.
                Poll::Pending
            }
        });
        let mut joined = seq_join(capacity, stream);
        let waker = fake_waker();
        let mut cx = Context::from_waker(&waker);

        let res = joined.poll_next_unpin(&mut cx);
        assert_count(&polled_r, 1);
        assert_count(&produced_r, 0);
        assert_count(&read_r, 0);
        assert!(res.is_pending());

        *v_w.lock().unwrap() = Some(7);
        let res = joined.poll_next_unpin(&mut cx);
        assert_count(&polled_r, 2);
        assert_count(&produced_r, 1);
        assert_count(&read_r, 1);
        assert!(matches!(res, Poll::Ready(Some(7))));
    }

    /// A fully synchronous test with a synthetic stream, all the way to the end.
    #[tokio::test]
    async fn complete_stream() {
        const VALUE: u32 = 20;
        const COUNT: usize = 7;
        let capacity = NonZeroUsize::new(3).unwrap();
        // Track the number of values produced.
        let produced_w: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let produced_r = Arc::clone(&produced_w);

        let stream = repeat_with(|| {
            *produced_w.lock().unwrap() += 1;
            lazy(|_| VALUE)
        })
        .take(COUNT);
        let mut joined = seq_join(capacity, stream);
        let waker = fake_waker();
        let mut cx = Context::from_waker(&waker);

        // The first poll causes the active buffer to be filled if that is possible.
        let res = joined.poll_next_unpin(&mut cx);
        assert_count(&produced_r, capacity.get());
        assert!(matches!(res, Poll::Ready(Some(VALUE))));

        // A few more iterations, where each top up the buffer.
        for _ in 0..(COUNT - capacity.get()) {
            let res = joined.poll_next_unpin(&mut cx);
            assert_count(&produced_r, 1);
            assert!(matches!(res, Poll::Ready(Some(VALUE))));
        }

        // Then we drain the buffer.
        for _ in 0..(capacity.get() - 1) {
            let res = joined.poll_next_unpin(&mut cx);
            assert_count(&produced_r, 0);
            assert!(matches!(res, Poll::Ready(Some(VALUE))));
        }

        // Then the stream ends.
        let res = joined.poll_next_unpin(&mut cx);
        assert_count(&produced_r, 0);
        assert!(matches!(res, Poll::Ready(None)));
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use std::{convert::Infallible, iter::once};

    use futures::{
        future::{lazy, BoxFuture},
        stream::{iter, poll_immediate},
        Future, StreamExt,
    };

    use super::*;
    use crate::test_executor::run;

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

    /// This test has to use multi-threaded runtime because early return causes `TryCollect` to be
    /// dropped and the remaining futures to be cancelled which can only happen if there is more
    /// than one thread available.
    ///
    /// This behavior is only applicable when `seq_try_join_all` uses more than one thread, for
    /// maintenance reasons, we use it even parallelism is turned off.
    #[test]
    fn try_join_early_abort() {
        const ERROR: &str = "error message";
        fn f(i: u32) -> impl Future<Output = Result<u32, &'static str>> {
            lazy(move |_| match i {
                1 => Ok(1),
                2 => Err(ERROR),
                _ => panic!("should have aborted earlier"),
            })
        }

        run(|| async {
            let active = NonZeroUsize::new(10).unwrap();
            let err = seq_try_join_all(active, (1..=3).map(f)).await.unwrap_err();
            assert_eq!(err, ERROR);
        });
    }

    #[test]
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

    /// This test demonstrates that forgetting the future returned by `parallel_join` is not safe and will cause
    /// use-after-free safety error.
    #[test]
    #[cfg(feature = "multi-threading")]
    fn parallel_join_forget_is_not_safe() {
        use std::mem::ManuallyDrop;

        use futures::future::poll_immediate;

        use crate::{seq_join::multi_thread::parallel_join, sync::Arc};

        run(|| async {
            const N: usize = 24;
            let borrow_from_me = Arc::new(vec![1, 2, 3]);
            let start = Arc::new(tokio::sync::Barrier::new(N + 1));
            // counts how many tasks have accessed `borrow_from_me` after it was destroyed.
            // this test expects all tasks to access `borrow_from_me` at least once.
            let bad_accesses = Arc::new(tokio::sync::Barrier::new(N + 1));

            let futures = (0..N)
                .map(|_| {
                    let borrowed = Arc::downgrade(&borrow_from_me);
                    let start = start.clone();
                    let bad_access = bad_accesses.clone();
                    async move {
                        start.wait().await;
                        // at this point, the parent future is forgotten and borrowed should point to nothing
                        for _ in 0..100 {
                            if borrowed.upgrade().is_none() {
                                bad_access.wait().await;
                                break;
                            }
                            tokio::task::yield_now().await;
                        }
                        Ok::<(), ()>(())
                    }
                })
                .collect::<Vec<_>>();

            let mut f = unsafe { parallel_join(futures) };
            poll_immediate(&mut f).await;
            start.wait().await;

            // forgetting f does not mean that futures spawned by `parallel_join` will be cancelled.
            let guard = ManuallyDrop::new(f);

            // Async executor will still be polling futures and they will try to follow this pointer.
            drop(borrow_from_me);

            // this test should terminate because all tasks should access `borrow_from_me` at least once.
            bad_accesses.wait().await;

            // do not leak memory
            let _ = ManuallyDrop::into_inner(guard);
        })
    }
}
