use futures::Stream;
use std::{
    future::Future,
    iter::repeat_with,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll, Waker},
};

/// FIFO queue that backs spsc channel. Uses the ring buffer and two pointers to last element written
/// and read.
struct Queue<T> {
    /// Pointer to the next write slot. If `head` == `tail`, queue is considered empty.
    head: AtomicUsize,
    /// Pointer to the next read slot. If `tail` - `head` == capacity, queue is considered full.
    tail: AtomicUsize,
    /// Ring buffer.
    buf: Box<[Mutex<Option<T>>]>,
    /// A task to wake when there is a next element to read from the queue.
    read_waker: Mutex<Option<Waker>>,
    /// A task to wake when there is at least one slot available in the queue to write.
    write_waker: Mutex<Option<Waker>>,
    /// Indicates that queue is closed.
    closed: AtomicBool,
}

impl<T> Queue<T> {
    fn queue_op<F: FnOnce(usize, usize) -> R, R>(&self, f: F) -> R {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        f(head, tail)
    }

    /// Writes a new value at `index` mod buffer size and returns the previous value.
    fn write(&self, index: usize, value: T) -> Option<T> {
        self.buf[index % self.buf.len()]
            .lock()
            .unwrap()
            .replace(value)
    }

    /// Takes the value stored at `index` mod size out and places `None` in that cell.
    /// This method has no effect if the value wasn't set before.
    fn take(&self, index: usize) -> Option<T> {
        self.buf[index % self.buf.len()]
            .lock()
            .unwrap()
            .take()
    }

    /// Closes this queue, making it unavailable for new writes. Queue can still be drained after
    /// this call. It is safe to call this method more than once.
    fn close(&self) {
        self.closed.swap(true, Ordering::Release);
    }

    /// Checks whether this queue is closed.
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

/// Sending end of the spsc channel. Allows messages to be pushed into the channel via [`push`].
/// Dropping the sender will wake the receiver and close the stream.
///
/// [`push`]: Sender::push
struct Sender<T> {
    state: Arc<Queue<T>>,
}

#[allow(dead_code)]
impl <T: Send> Sender<T> {
    fn push(&self, value: T) -> Push<'_, T> {
        Push {
            value: Some(value),
            sender: self,
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        self.state.close();
    }
}

/// Receiving end of the spsc channel. Items can be taken out of it using the standard [`Stream`]
/// API.
///
/// Dropping the receiver handle prematurely will cause a panic on the producer's side. This behaviour
/// is chosen because it suits the IPA use-case where downstream tasks live longer than upstream.
///
/// [`Stream`]: Stream
struct Receiver<T> {
    state: Arc<Queue<T>>,
}

impl <T: Send> Stream for Receiver<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let state = &self.state;
        let v = state.queue_op(|head, tail| {
            if head == tail {
                if state.is_closed() {
                    Poll::Ready(None)
                } else {
                    save_waker(&state.read_waker, cx.waker());
                    Poll::Pending
                }
            } else {
                let item = state.take(head);
                debug_assert!(item.is_some());

                state.head.store(head.wrapping_add(1), Ordering::Release);
                Poll::Ready(item)
            }
        });
        wake(&state.write_waker);

        v
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        self.state.close();
    }
}

/// Creates a new single-producer single-consumer channel with the given capacity and returns
/// its sending and receiving ends. Up to `capacity` elements can be added to this channel without
/// waiting by using [`push`]. The receiving end is a stream that takes these elements out in FIFO
/// order.
///
/// If channel is full, [`push`] waits until at least one element is taken out by polling
/// the receiver. Channel is closed automatically when either [`Sender`] or [`Receiver`] is dropped.
/// Closed channel will reject [`push`] requests, but will let the receiver drain the remaining items.
///
/// ### Performance considerations
///
/// This channel is backed by a ring buffer. Although it uses mutexes internally, they are not
/// contended between reader and writer. Slow writer may cause excessive context switching between
/// read and write tasks, if that becomes a problem, consider additional buffering or extending the
/// API to push several items at a time per single reader wake.
///
/// Sender and receiver may over-communicate the updates in contention which happens
/// when the capacity is small. See `contention` test for more details.
///
/// [`push`]: Sender::push
/// [`Sender`]: Sender
/// [`Receiver`]: Receiver
#[allow(dead_code)]
fn channel<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
    let state = Arc::new(Queue {
        head: AtomicUsize::new(0),
        tail: AtomicUsize::new(0),
        buf: repeat_with(|| Mutex::new(None))
            .take(capacity)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        read_waker: Mutex::new(None),
        write_waker: Mutex::new(None),
        closed: AtomicBool::new(false),
    });

    (
        Sender {
            state: Arc::clone(&state),
        },
        Receiver { state },
    )
}

/// Future for [`push`] method.
///
/// [`push`]: Sender::push
#[must_use = "futures do nothing unless polled"]
pub struct Push<'a, T> {
    value: Option<T>,
    sender: &'a Sender<T>,
}

impl<T: Send + Unpin> Future for Push<'_, T> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        assert!(!self.sender.state.is_closed(), "Channel is closed");
        let state = &self.sender.state;
        let value = &mut self.value;

        let v = state.queue_op(|head, tail| {
            if tail.wrapping_sub(head) == state.buf.len() {
                // buffer is full, we have no capacity to write
                save_waker(&state.write_waker, cx.waker());
                Poll::Pending
            } else {
                let value = value.take().expect("value hasn't been moved yet");
                let prev = state.write(tail, value);
                debug_assert!(prev.is_none());

                state.tail.store(tail.wrapping_add(1), Ordering::Release);
                Poll::Ready(())
            }
        });

        wake(&self.sender.state.read_waker);

        v
    }
}

fn wake(cell: &Mutex<Option<Waker>>) {
    if let Some(waker) = cell.lock().unwrap().take() {
        waker.wake();
    }
}

fn save_waker(cell: &Mutex<Option<Waker>>, waker: &Waker) {
    *cell.lock().unwrap() = Some(waker.clone());
}

#[cfg(all(test, any(unit_test, feature = "shuttle")))]
mod tests {
    use super::*;
    use crate::{
        rand::thread_rng,
        test_executor::{run, spawn},
    };
    use futures_util::{
        future::{poll_immediate, try_join},
        StreamExt,
    };
    use rand::Rng;
    use std::pin::pin;

    #[test]
    fn sender_fills_buffer() {
        run(|| async {
            let (tx, _rx) = channel::<u32>(100);

            for i in 0..100 {
                tx.push(i).await;
            }

            let mut f = pin!(tx.push(100));
            assert_eq!(None, poll_immediate(&mut f).await);
        });
    }

    #[test]
    fn receiver_unblocks_sender() {
        run(|| async {
            let (tx, mut rx) = channel(1);

            let send_handle = spawn(async move {
                tx.push(1).await;
                tx.push(2).await;
            });

            assert_eq!(Some(1), rx.next().await);
            send_handle.await.unwrap();
        });
    }

    #[test]
    fn sender_unblocks_receiver() {
        run(|| async {
            let (tx, mut rx) = channel(1);

            let recv_handle = spawn(async move { rx.next().await });

            tx.push(1).await;
            assert_eq!(Some(1), recv_handle.await.unwrap());
        });
    }

    #[test]
    #[should_panic(expected = "Channel is closed")]
    #[cfg(not(feature = "shuttle"))]
    fn dropping_receiver_unblocks_sender() {
        use std::panic;

        run(|| async {
            let (tx, rx) = channel(1);
            tx.push(1).await;
            let send_handle = spawn(async move {
                tx.push(2).await;
            });

            drop(rx);
            panic::resume_unwind(send_handle.await.unwrap_err().into_panic());
        });
    }

    #[test]
    fn random() {
        run(|| async {
            let fwd_capacity = thread_rng().gen_range(1..=100);
            let (fwd_tx, mut fwd_rx) = channel(fwd_capacity);

            let a_handle = spawn(async move {
                let iterations = thread_rng().gen_range(fwd_capacity..=5 * fwd_capacity);
                let mut sum: u64 = 0;
                for _ in 0..iterations {
                    sum = sum.wrapping_add(1);
                    fwd_tx.push(1).await;
                }

                sum
            });

            let b_handle = spawn(async move {
                let mut sum: u64 = 0;
                while let Some(value) = fwd_rx.next().await {
                    sum = sum.wrapping_add(value);
                }

                sum
            });

            let (a, b) = try_join(a_handle, b_handle).await.unwrap();
            assert_eq!(a, b);
        });
    }

    #[test]
    fn contention() {
        run(|| async {
            let (tx, mut rx) = channel(1);
            // writer throughput is 2x compared to reader.
            // this causes head and tail pointers to be read/written by two threads often at
            // the same time. Without excessive wakes, this test will stall.
            spawn(async move {
                for i in 0..100 {
                    tx.push(i).await;
                    tx.push(100 + i).await;
                }
            });
            let read_handle = spawn(async move {
                let mut sum = 0;
                while let Some(value) = rx.next().await {
                    sum += value;
                }

                sum
            });

            assert_eq!(19900, read_handle.await.unwrap());
        });
    }
}
