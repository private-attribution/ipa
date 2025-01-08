use std::{
    collections::VecDeque,
    future::IntoFuture,
    marker::PhantomData,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{stream::Fuse, Future, Stream, StreamExt};
use pin_project::pin_project;

use crate::telemetry::memory::periodic_memory_report;

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
            unreachable!("take should be only called once.");
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
    source: Fuse<S>,
    active: VecDeque<ActiveItem<F>>,
    spawned: usize,
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
            spawned: 0,
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
                periodic_memory_report(*this.spawned);
                *this.spawned += 1;
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
            periodic_memory_report(*this.spawned);
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

#[cfg(all(test, unit_test))]
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
        Future, StreamExt,
    };

    use crate::{
        seq_join::{seq_join, seq_try_join_all},
        test_executor::run,
    };

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
}
