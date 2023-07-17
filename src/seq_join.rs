use crate::exact::ExactSizeStream;
use futures::{
    stream::{iter, Iter as StreamIter, TryCollect},
    Future, Stream, StreamExt, TryStreamExt,
};
use pin_project::pin_project;
use std::{
    collections::VecDeque,
    future::IntoFuture,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};

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
/// [`try_join_all`]: futures::future::try_join_all
/// [`Stream`]: futures::stream::Stream
/// [`StreamExt::buffered`]: futures::stream::StreamExt::buffered
pub fn seq_join<S, F, O>(active: NonZeroUsize, source: S) -> SequentialFutures<S, F>
where
    S: Stream<Item = F> + Send,
    F: Future<Output = O>,
{
    SequentialFutures {
        source: source.fuse(),
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

type SeqTryJoinAll<I, F> = SequentialFutures<StreamIter<<I as IntoIterator>::IntoIter>, F>;

/// A substitute for [`futures::future::try_join_all`] that uses [`seq_join`].
/// This awaits all the provided futures in order,
/// aborting early if any future returns `Result::Err`.
pub fn seq_try_join_all<I, F, O, E>(
    active: NonZeroUsize,
    source: I,
) -> TryCollect<SeqTryJoinAll<I, F>, Vec<O>>
where
    I: IntoIterator<Item = F> + Send,
    I::IntoIter: Send,
    F: Future<Output = Result<O, E>>,
{
    seq_join(active, iter(source)).try_collect()
}

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
        let ActiveItem::Pending(f) = self else { return true; };
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
pub struct SequentialFutures<S, F>
where
    S: Stream<Item = F> + Send,
    F: IntoFuture,
{
    #[pin]
    source: futures::stream::Fuse<S>,
    active: VecDeque<ActiveItem<F>>,
}

impl<S, F> Stream for SequentialFutures<S, F>
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

impl<S, F> ExactSizeStream for SequentialFutures<S, F>
where
    S: Stream<Item = F> + Send + ExactSizeStream,
    F: IntoFuture,
{
}

#[cfg(all(test, unit_test))]
mod test {
    use crate::seq_join::{seq_join, seq_try_join_all};
    use futures::{
        future::{lazy, BoxFuture},
        stream::{iter, poll_fn, poll_immediate, repeat_with},
        Future, StreamExt,
    };
    use std::{
        convert::Infallible,
        iter::once,
        num::NonZeroUsize,
        ptr::null,
        sync::{Arc, Mutex},
        task::{Context, Poll, Waker},
    };

    async fn immediate(count: u32) {
        let capacity = NonZeroUsize::new(3).unwrap();
        let values = seq_join(capacity, iter((0..count).map(|i| async move { i })))
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
    async fn out_of_order() {
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
    }

    #[tokio::test]
    async fn join_success() {
        fn f<T: Send>(v: T) -> impl Future<Output = Result<T, Infallible>> {
            lazy(move |_| Ok(v))
        }

        let active = NonZeroUsize::new(10).unwrap();
        let res = seq_try_join_all(active, (1..5).map(f)).await.unwrap();
        assert_eq!((1..5).collect::<Vec<_>>(), res);
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
        let err = seq_try_join_all(active, (1..=3).map(f)).await.unwrap_err();
        assert_eq!(err, ERROR);
    }

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
    #[test]
    fn complete_stream() {
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
