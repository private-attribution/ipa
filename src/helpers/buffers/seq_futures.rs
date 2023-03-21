use futures::{
    stream::{iter, Fuse},
    Future, Stream, StreamExt,
};
use pin_project::pin_project;
use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};

/// Sequentially join futures from an iterator.
///
/// This function polls futures from a stream in strict sequence.
/// If any future blocks, up to `active - 1` futures after it will be polled so
/// that they make progress.
///
/// Unlike [`StreamExt::buffered`], Futures from the stream must resolve in the
/// same order in which they are produced.
///
/// This API accepts an active stream count and a [`Stream`] instance,
/// from which `Future`s are drawn.
/// To replicate the effect of [`join_all`], an input `Iterator` can be adapted using
/// [`futures::stream::iter`]; the output can be collected into a [`Vec`] (or any
/// collection) using [`StreamExt::collect`], as follows:
///
/// ```ignore
/// # // Ignore because this module is private to the crate.
/// # async fn join_all() {
/// # use std::num::NonZeroUsize;
/// # use raw_ipa::helpers::buffers::seq_join;
/// use futures::stream::{StreamExt, iter};
///
/// let capacity = NonZeroUsize::new(5).unwrap();
/// let it = (0..3).map(|x| async move { x });
/// let res = seq_join(capacity, iter(it)).collect::<Vec<_>>().await;
/// assert_eq!(&res, &[0, 1, 2]);
/// # }
/// ```
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
/// [`Stream`]: futures::stream::Stream
/// [`futures::stream::iter`]: futures::stream::iter::iter
/// [`StreamExt::collect`]: futures::stream::StreamExt::collect
/// [`StreamExt::buffered`]: futures::stream::StreamExt::buffered
pub fn seq_join<S, Fut, O>(active: NonZeroUsize, stream: S) -> SequentialFutures<S, Fut, O>
where
    S: Stream<Item = Fut>,
    Fut: Future<Output = O>,
{
    SequentialFutures {
        stream: stream.fuse(),
        active: VecDeque::with_capacity(active.get()),
    }
}

/// A substitute for [`futures::future::try_join_all`] that uses [`seq_join`].
///
/// [`seq_join`]: raw_ipa::helpers::buffers::seq_join
pub async fn try_join_all<I, O, E>(futures: I) -> Result<Vec<O>, E>
where
    I: IntoIterator,
    I::Item: Future<Output = Result<O, E>>,
{
    const ACTIVE: Option<NonZeroUsize> = NonZeroUsize::new(256);

    let futures = futures.into_iter();
    let (lower, upper) = futures.size_hint();
    let mut res = Vec::with_capacity(lower.saturating_add(upper.unwrap_or(0)));
    let mut s = seq_join(ACTIVE.unwrap(), iter(futures));
    while let Some(r) = s.next().await {
        res.push(r?);
    }
    Ok(res)
}

#[pin_project]
pub struct SequentialFutures<S, Fut, O>
where
    S: Stream<Item = Fut>,
    Fut: Future<Output = O>,
{
    #[pin]
    stream: Fuse<S>,
    active: VecDeque<Pin<Box<Fut>>>,
}

impl<S, Fut, O> Stream for SequentialFutures<S, Fut, O>
where
    S: Stream<Item = Fut>,
    Fut: Future<Output = O>,
{
    type Item = O;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // Draw more values from the input, up to the capacity.
        while this.active.len() < this.active.capacity() {
            if let Poll::Ready(Some(f)) = this.stream.as_mut().poll_next(cx) {
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
                    assert!(res.is_pending(), "future resolved out of order");
                }
                Poll::Pending
            }
        } else if this.stream.is_done() {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let in_progress = self.active.len();
        let (lower, upper) = self.stream.size_hint();
        (
            lower.saturating_add(in_progress),
            upper.and_then(|u| u.checked_add(in_progress)),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::helpers::buffers::seq_futures::{seq_join, try_join_all};
    use futures::{
        future::{lazy, pending, BoxFuture},
        stream::{iter, poll_fn, repeat_with},
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
    #[should_panic(expected = "future resolved out of order")]
    async fn out_of_order() {
        let capacity = NonZeroUsize::new(3).unwrap();
        let unresolved: BoxFuture<'_, u32> = Box::pin(pending());
        let it = once(unresolved)
            .chain((0..3_u32).map(|i| -> BoxFuture<'_, u32> { Box::pin(async move { i }) }));
        drop(seq_join(capacity, iter(it)).collect::<Vec<_>>().await);
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

    #[tokio::test]
    async fn join_success() {
        fn ok(v: u32) -> impl Future<Output = Result<u32, Infallible>> {
            lazy(move |_| Ok(v))
        }

        let res = try_join_all([ok(1), ok(2), ok(3)]).await.unwrap();
        assert_eq!(vec![1, 2, 3], res);
    }

    #[tokio::test]
    async fn join_early_abort() {
        const ERROR: &str = "error message";
        fn f(i: u32) -> impl Future<Output = Result<u32, &'static str>> {
            lazy(move |_| match i {
                1 => Ok(1),
                2 => Err(ERROR),
                _ => panic!("should have aborted earlier"),
            })
        }

        let err = try_join_all([f(1), f(2), f(3)]).await.unwrap_err();
        assert_eq!(err, ERROR);
    }
}
