use std::{
    future::{Future, IntoFuture},
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{stream::Fuse, Stream, StreamExt};
use pin_project::pin_project;
use tracing::{Instrument, Span};

use crate::telemetry::memory::periodic_memory_report;

#[cfg(feature = "shuttle")]
mod shuttle_spawner {
    use std::future::Future;

    use shuttle_crate::future::{self, JoinError, JoinHandle};

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
#[must_use = "Futures do nothing unless polled"]
pub struct SequentialFutures<'fut, S, F>
where
    S: Stream<Item = F> + Send + 'fut,
    F: IntoFuture,
    <<F as IntoFuture>::IntoFuture as Future>::Output: Send + 'static,
{
    #[pin]
    spawner: Spawner<'fut, F::Output>,
    #[pin]
    source: Fuse<S>,
    capacity: usize,
    spawned: usize,
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
            spawned: 0,
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
        #[cfg(feature = "shuttle")]
        use crate::shim::Tokio;

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
                let task_index = *this.spawned;
                this.spawner
                    .spawn_cancellable(f.into_future().instrument(Span::current()), move || {
                        panic!("SequentialFutures: spawned task {task_index} cancelled")
                    });

                periodic_memory_report(*this.spawned);
                *this.spawned += 1;
            } else {
                break;
            }
        }

        // Poll spawner if it has work to do. If both source and spawner are empty, we're done.
        if this.spawner.remaining() > 0 {
            this.spawner.as_mut().poll_next(cx).map(|v| match v {
                Some(Ok(v)) => Some(v),
                Some(Err(e)) => {
                    if let Ok(reason) = e.try_into_panic() {
                        std::panic::resume_unwind(reason);
                    } else {
                        panic!("SequentialFutures: spawned task is cancelled")
                    }
                }
                None => None,
            })
        } else if this.source.is_done() {
            periodic_memory_report(*this.spawned);
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

pub(super) unsafe fn parallel_join<'fut, I, F, O, E>(
    iterable: I,
) -> impl Future<Output = Result<Vec<O>, E>> + Send + 'fut
where
    I: IntoIterator<Item = F> + Send,
    F: Future<Output = Result<O, E>> + Send + 'fut,
    O: Send + 'static,
    E: Send + 'static,
{
    let mut scope = {
        let mut scope = unsafe { create_spawner() };
        for element in iterable {
            // it is important to make those cancellable to avoid deadlocks if one of the spawned future panics.
            // If there is a dependency between futures, pending one will never complete.
            // Cancellable futures will be cancelled when spawner is dropped which is the behavior we want.
            scope.spawn_cancellable(element.instrument(Span::current()), || {
                panic!("parallel_join: task cancelled")
            });
        }
        scope
    };

    async move {
        let mut result = Vec::with_capacity(scope.len());
        while let Some(item) = scope.next().await {
            // join error is nothing we can do about
            result.push(item.expect("parallel_join: received JoinError")?);
        }
        Ok(result)
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::{future::Future, num::NonZeroUsize, pin::Pin, time::Duration};

    use futures_util::future::lazy;

    use crate::{seq_join::seq_try_join_all, test_executor::run};

    /// This test demonstrates that forgetting the future returned by `parallel_join` is not safe and will cause
    /// use-after-free safety error. It spawns a few tasks that constantly try to access the `borrow_from_me` weak
    /// reference while the main thread drops the owning reference. By proving that futures are able to see the weak
    /// pointer unset, this test shows that same can happen for regular references and cause use-after-free.
    #[test]
    fn parallel_join_forget_is_not_safe() {
        use futures::future::poll_immediate;

        use crate::{seq_join::multi_thread::parallel_join, sync::Arc};

        run(|| async {
            const N: usize = 24;
            let borrowed_vec = Box::new([1, 2, 3]);
            let borrow_from_me = Arc::new(vec![1, 2, 3]);
            let start = Arc::new(tokio::sync::Barrier::new(N + 1));
            // counts how many tasks have accessed `borrow_from_me` after it was destroyed.
            // this test expects all tasks to access `borrow_from_me` at least once.
            let bad_accesses = Arc::new(tokio::sync::Barrier::new(N + 1));

            let futures = (0..N)
                .map(|_| {
                    let borrowed = Arc::downgrade(&borrow_from_me);
                    let regular_ref = &borrowed_vec;
                    let start = start.clone();
                    let bad_access = bad_accesses.clone();
                    async move {
                        start.wait().await;
                        for _ in 0..100 {
                            if borrowed.upgrade().is_none() {
                                bad_access.wait().await;
                                // switch to `true` if you want to see the real corruption.
                                #[allow(unreachable_code)]
                                if false {
                                    // this is a place where we can see the use-after-free.
                                    // we avoid executing this block to appease sanitizers, but compiler happily
                                    // allows us to follow this reference.
                                    println!("{:?}", regular_ref);
                                }
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                        Ok::<_, ()>(())
                    }
                })
                .collect::<Vec<_>>();

            let mut f = Box::pin(unsafe { parallel_join(futures) });
            poll_immediate(&mut f).await;
            start.wait().await;

            // the type of `f` above captures the lifetime for borrowed_vec. Leaking `f` allows `borrowed_vec` to be
            // dropped, but that drop prohibits any subsequent manipulations with `f` pointer, irrespective of whether
            // `f` is `&mut _` or `*mut _` (value already borrowed error).
            // I am not sure I fully understand what is going on here (why borrowck allows me to leak the value, but
            // then I can't drop it even if it is a raw pointer), but removing the lifetime from `f` type allows
            // the test to pass.
            //
            // This is only required to do the proper cleanup and avoid memory leaks. Replacing this line with
            // `mem::forget(f)` will lead to the same test outcome, but Miri will complain about memory leaks.
            let f: _ = unsafe {
                std::mem::transmute::<_, Pin<Box<dyn Future<Output = Result<Vec<()>, ()>> + Send>>>(
                    Box::pin(f) as Pin<Box<dyn Future<Output = Result<Vec<()>, ()>>>>,
                )
            };

            // Async executor will still be polling futures and they will try to follow this pointer.
            drop(borrow_from_me);
            drop(borrowed_vec);

            // this test should terminate because all tasks should access `borrow_from_me` at least once.
            bad_accesses.wait().await;

            drop(f);
        });
    }

    #[test]
    #[should_panic(expected = "panic in task 1")]
    fn panic_from_task_unwinds_to_main() {
        fn f(i: u32) -> impl Future<Output = Result<u32, &'static str>> {
            lazy(move |_| match i {
                1 => panic!("panic in task 1"),
                i => Ok(i),
            })
        }

        run(|| async {
            let active = NonZeroUsize::new(10).unwrap();
            let _ = seq_try_join_all(active, (1..=3).map(f)).await;
            assert!(false, "Should have aborted earlier");
        });
    }
}
