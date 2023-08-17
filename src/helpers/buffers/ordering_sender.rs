#![allow(dead_code)] // TODO remove

use std::{
    borrow::Borrow,
    cmp::Ordering,
    collections::VecDeque,
    mem::drop,
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::{task::Waker, Future, Stream};
use generic_array::GenericArray;
use typenum::Unsigned;

use crate::{
    helpers::Message,
    sync::{
        atomic::{
            AtomicUsize,
            Ordering::{AcqRel, Acquire},
        },
        Mutex, MutexGuard,
    },
};

/// The operating state for an `OrderingSender`.
struct State {
    /// A store of bytes to write into.
    buf: Vec<u8>,
    /// The portion of the buffer that is marked "spare".
    /// Once `written + spare` is greater than the buffer capacity,
    /// data is available to the stream.
    spare: NonZeroUsize,
    /// How many bytes have been written and are available.
    written: usize,
    /// The sender is closed.
    closed: bool,
    /// An entity to wake when the buffer is read from.
    write_ready: Option<Waker>,
    /// Another entity to wake when the buffer is read from.
    stream_ready: Option<Waker>,
}

impl State {
    fn new(capacity: NonZeroUsize, spare: NonZeroUsize) -> Self {
        Self {
            buf: vec![0; capacity.get() + spare.get()],
            spare,
            written: 0,
            closed: false,
            write_ready: None,
            stream_ready: None,
        }
    }

    fn save_waker(v: &mut Option<Waker>, cx: &Context<'_>) {
        // here used to be a check that new waker will wake the same task.
        // however, the contract for `will_wake` states that it is a best-effort and even if
        // both wakes wake the same task, `will_wake` may still return `false`.
        // This is exactly what happened once we started using HTTP/2 - somewhere deep inside hyper
        // h2 implementation, there is a new waker (with the same vtable) that is used to poll
        // this stream again. This does not happen when we use HTTP/1.1, but it does not matter for
        // this code.
        v.replace(cx.waker().clone());
    }

    fn wake(v: &mut Option<Waker>) {
        if let Some(w) = v.take() {
            w.wake();
        }
    }

    fn write<M: Message>(&mut self, m: &M, cx: &Context<'_>) -> Poll<()> {
        assert!(
            M::Size::USIZE < self.spare.get(),
            "expect message size {:?} to be less than spare {:?}",
            M::Size::USIZE,
            self.spare.get()
        );
        let b = &mut self.buf[self.written..];
        if M::Size::USIZE <= b.len() {
            self.written += M::Size::USIZE;
            m.serialize(GenericArray::from_mut_slice(&mut b[..M::Size::USIZE]));

            if self.written + self.spare.get() >= self.buf.len() {
                Self::wake(&mut self.stream_ready);
            }
            Poll::Ready(())
        } else {
            Self::save_waker(&mut self.write_ready, cx);
            Poll::Pending
        }
    }

    fn take(&mut self, cx: &Context<'_>) -> Poll<Vec<u8>> {
        if self.written > 0 && (self.written + self.spare.get() >= self.buf.len() || self.closed) {
            let v = self.buf[..self.written].to_vec();
            self.written = 0;

            Self::wake(&mut self.write_ready);
            Poll::Ready(v)
        } else {
            Self::save_waker(&mut self.stream_ready, cx);
            Poll::Pending
        }
    }

    fn close(&mut self) {
        debug_assert!(!self.closed);
        self.closed = true;
        Self::wake(&mut self.stream_ready);
    }
}

/// An saved waker for a given index.
struct WakerItem {
    /// The index.
    i: usize,
    /// The waker.
    w: Waker,
}

/// A collection of saved wakers.
#[derive(Default)]
struct WaitingShard {
    /// The saved wakers.  These are sorted on insert (see `add`) and
    /// presumably removed constantly, so a circular buffer is used.
    wakers: VecDeque<WakerItem>,
}

impl WaitingShard {
    fn add(&mut self, i: usize, w: Waker) {
        // Each new addition will tend to have a larger index, so search backwards and
        // replace an equal index or insert after a smaller index.
        // TODO: consider a binary search if the item cannot be added to the end.
        let item = WakerItem { i, w };
        for j in (0..self.wakers.len()).rev() {
            match self.wakers[j].i.cmp(&i) {
                Ordering::Greater => (),
                Ordering::Equal => {
                    assert!(item.w.will_wake(&self.wakers[j].w));
                    self.wakers[j] = item;
                    return;
                }
                Ordering::Less => {
                    self.wakers.insert(j + 1, item);
                    return;
                }
            }
        }
        self.wakers.insert(0, item);
    }

    fn wake(&mut self, i: usize) {
        if let Some(idx) = self
            .wakers
            .iter()
            .take_while(|wi| wi.i <= i)
            .position(|wi| wi.i == i)
        {
            // We only save one waker at each index, but if a future is polled without
            // this function having to wake the task, it will sit here.  Clean those out.
            drop(self.wakers.drain(0..idx));
            self.wakers.pop_front().unwrap().w.wake();
        }
    }
}

/// A collection of wakers that are indexed by the send index (`i`).
/// This structure aims to reduce mutex contention by including a number of shards.
#[derive(Default)]
struct Waiting {
    shards: [Mutex<WaitingShard>; Self::SHARDS],
}

impl Waiting {
    const SHARDS: usize = 8;
    /// The number of low bits to ignore when indexing into shards.
    /// This will ensure that consecutive items will hit the same shard (and mutex)
    /// when we operate.
    /// TODO - this should be close to the number we use for the active items in
    /// `seq_join()`.
    const CONTIGUOUS_BITS: u32 = 6;

    /// Find a shard.  This ensures that sequential values pick the same shard
    /// in a contiguous block.
    fn shard(&self, i: usize) -> MutexGuard<WaitingShard> {
        let idx = (i >> Self::CONTIGUOUS_BITS) % Self::SHARDS;
        self.shards[idx].lock().unwrap()
    }

    fn add(&self, i: usize, w: Waker) {
        self.shard(i).add(i, w);
    }

    fn wake(&self, i: usize) {
        self.shard(i).wake(i);
    }
}

/// An `OrderingSender` accepts messages for sending in any order, but
/// ensures that they are serialized based on an index.
///
/// # Performance
///
/// `OrderingSender` maintains a buffer that includes a write threshold
/// (`write_size`) with spare capacity (`spare`) to allow for writing of
/// messages that are not a multiple of `write_size` and extra buffering.
/// Data in excess of `write_size` will be passed to the stream without
/// segmentation, so a stream implementation needs to be able to handle
/// `write_size + spare` bytes at a time.
///
/// Data less than the `write_size` threshold only becomes available to
/// the stream when the sender is closed (with [`close`]).
///
/// The `spare` capacity determines the size of messages that can be sent;
/// see [`send`] for details.
///
/// [`new`]: OrderingSender::new
/// [`send`]: OrderingSender::send
/// [`close`]: OrderingSender::close
pub struct OrderingSender {
    next: AtomicUsize,
    state: Mutex<State>,
    waiting: Waiting,
}

impl OrderingSender {
    /// Make an `OrderingSender` with a capacity of `capacity` (in bytes).
    #[must_use]
    pub fn new(write_size: NonZeroUsize, spare: NonZeroUsize) -> Self {
        Self {
            next: AtomicUsize::new(0),
            state: Mutex::new(State::new(write_size, spare)),
            waiting: Waiting::default(),
        }
    }

    /// Send a message, `m`, at the index `i`.  
    /// This method blocks until all previous messages are sent and until sufficient
    /// space becomes available in the sender's buffer.
    ///
    /// # Panics
    ///
    /// Polling the future this method returns will panic if
    /// * the message is larger than the spare capacity (see below), or
    /// * the same index is provided more than once.
    ///
    /// This code could deadlock if a message is larger than the spare capacity.
    /// This occurs when a message cannot reliably be written to the buffer
    /// because it would overflow the buffer.  The data already in the buffer
    /// might not reach the threshold for sending, which means that progress
    /// is impossible.  Polling the promise returned will panic if the spare
    /// capacity is insufficient.
    pub fn send<M: Message>(&self, i: usize, m: M) -> Send<'_, M> {
        Send { i, m, sender: self }
    }

    /// Close the sender at index `i`.
    /// This method blocks until all previous messages are sent.
    ///
    /// # Panics
    /// Polling the future this method returns will panic if a message has already
    /// been sent with an equal or higher index.
    pub fn close(&self, i: usize) -> Close<'_> {
        Close { i, sender: self }
    }

    /// Perform the next `send` or `close` operation.
    fn next_op<F>(&self, i: usize, cx: &Context<'_>, f: F) -> Poll<()>
    where
        F: FnOnce(&mut MutexGuard<'_, State>) -> Poll<()>,
    {
        // This load here is on the hot path.
        // Don't acquire the state mutex unless this test passes.
        match self.next.load(Acquire).cmp(&i) {
            Ordering::Greater => {
                panic!("attempt to write/close at index {i} twice");
            }
            Ordering::Equal => {
                // OK, now it is our turn, so we need to hold a lock.
                // No one else should be incrementing this atomic, so
                // there should be no contention on this lock except for
                // any calls to `take()`, which is tolerable.
                let res = f(&mut self.state.lock().unwrap());
                if res.is_ready() {
                    let curr = self.next.fetch_add(1, AcqRel);
                    debug_assert_eq!(i, curr, "we just checked this");
                }
                res
            }
            Ordering::Less => {
                // This is the hot path. Wait our turn.
                self.waiting.add(i, cx.waker().clone());
                Poll::Pending
            }
        }
    }

    /// Take the next chunk of data that the sender has produced.
    /// This function implements most of what [`OrderedStream`] needs.
    ///
    /// ## Panics
    /// If the internal mutex is poisoned or locked by this thread already.
    pub fn take_next(&self, cx: &Context<'_>) -> Poll<Option<Vec<u8>>> {
        let mut b = self.state.lock().unwrap();

        if let Poll::Ready(v) = b.take(cx) {
            self.waiting.wake(self.next.load(Acquire));
            Poll::Ready(Some(v))
        } else if b.closed {
            Poll::Ready(None)
        } else {
            // `b.take()` will have tracked the waker
            Poll::Pending
        }
    }

    /// The stream interface requires a mutable reference to the stream itself.
    /// That's not possible here as we create a ton of immutable references to this.
    /// This wrapper takes a trivial reference so that we can implement `Stream`.
    pub(crate) fn as_stream(&self) -> OrderedStream<&Self> {
        OrderedStream { sender: self }
    }

    pub(crate) fn as_rc_stream(self: Arc<Self>) -> OrderedStream<Arc<Self>> {
        OrderedStream { sender: self }
    }
}

/// A future for writing item `i` into an `OrderingSender`.
pub struct Send<'s, M: Message> {
    i: usize,
    m: M,
    sender: &'s OrderingSender,
}

impl<'s, M: Message> Future for Send<'s, M> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut();

        let res = this.sender.next_op(this.i, cx, |b| {
            assert!(!b.closed, "writing on a closed stream");
            b.write(&this.m, cx)
        });
        // A successful write: wake the next in line.
        // But not while holding the lock on state.
        if res.is_ready() {
            this.sender.waiting.wake(this.i + 1);
        }
        res
    }
}

/// A future for writing item `i` into an `OrderingSender`.
pub struct Close<'s> {
    i: usize,
    sender: &'s OrderingSender,
}

impl<'s> Future for Close<'s> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut();
        this.sender.next_op(this.i, cx, |b| {
            b.close();
            Poll::Ready(())
        })
    }
}

/// An `OrderingSender` as a `Stream`.
///
/// This is a little odd in that it can be misused by creating multiple streams
/// from the same `OrderingSender`.  If that happens messages are distributed to
/// the next stream that happens to be polled.  Ordinarily streams require a
/// mutable reference so that they have exclusive access to the underlying state.
/// To avoid that happening, don't make more than one stream.
pub struct OrderedStream<B: Borrow<OrderingSender>> {
    sender: B,
}

impl<B: Borrow<OrderingSender> + Unpin> Stream for OrderedStream<B> {
    type Item = Vec<u8>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::get_mut(self).sender.borrow().take_next(cx)
    }
}

#[cfg(all(test, any(unit_test, feature = "shuttle")))]
mod test {
    use std::{iter::zip, num::NonZeroUsize};

    use futures::{
        future::{join, join3, join_all},
        stream::StreamExt,
        FutureExt,
    };
    use generic_array::GenericArray;
    use rand::Rng;
    use typenum::Unsigned;

    use super::OrderingSender;
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime, Serializable},
        rand::thread_rng,
        sync::Arc,
        test_executor::run,
    };

    fn sender() -> Arc<OrderingSender> {
        Arc::new(OrderingSender::new(
            NonZeroUsize::new(6).unwrap(),
            NonZeroUsize::new(5).unwrap(),
        ))
    }

    /// Writing a single value cannot be read until the stream closes.
    #[test]
    fn send_recv() {
        run(|| async {
            let input = Fp31::truncate_from(7_u128);
            let sender = sender();
            sender.send(0, input).await;
            assert!(sender.as_stream().next().now_or_never().is_none());
        });
    }

    /// Generate a send and close the stream.
    #[test]
    fn send_close_recv() {
        run(|| async {
            let input = Fp31::truncate_from(7_u128);
            let sender = sender();
            let send = sender.send(0, input);
            let stream = sender.as_stream();
            let close = sender.close(1);
            let send_close = join(send, close);
            let (_, taken) = join(send_close, stream.collect::<Vec<_>>()).await;
            let flat = taken.into_iter().flatten().collect::<Vec<_>>();
            let output = Fp31::deserialize(GenericArray::from_slice(&flat));
            assert_eq!(input, output);
        });
    }

    /// Initiate a close before sending.
    #[test]
    fn close_send_recv() {
        run(|| async {
            let input = Fp31::truncate_from(7_u128);
            let sender = sender();
            let close = sender.close(1);
            let send = sender.send(0, input);
            let close_send = join(close, send);
            let (_, taken) = join(close_send, sender.as_stream().collect::<Vec<_>>()).await;
            let flat = taken.into_iter().flatten().collect::<Vec<_>>();
            let output = Fp31::deserialize(GenericArray::from_slice(&flat));
            assert_eq!(input, output);
        });
    }

    #[test]
    #[should_panic(expected = "attempt to write/close at index 2 twice")]
    fn double_send() {
        run(|| async {
            let sender = sender();
            let send_many =
                join_all((0..3_u8).map(|i| sender.send(usize::from(i), Fp31::truncate_from(i))));
            let send_again = sender.send(2, Fp31::truncate_from(2_u128));
            join(send_many, send_again).await;
        });
    }

    #[test]
    #[should_panic(expected = "attempt to write/close at index 2 twice")]
    fn close_over_send() {
        run(|| async {
            let sender = sender();
            let send_many =
                join_all((0..3_u8).map(|i| sender.send(usize::from(i), Fp31::truncate_from(i))));
            let close_it = sender.close(2);
            join(send_many, close_it).await;
        });
    }

    #[test]
    #[should_panic(expected = "writing on a closed stream")]
    fn send_after_close() {
        run(|| async {
            let sender = sender();
            // We can't use `join()` here because the close task won't bother to
            // wake the send task if the send is polled first.
            sender.close(0).await;
            sender.send(1, Fp31::truncate_from(1_u128)).await;
        });
    }

    /// Messages can be any size.  The sender doesn't care.
    #[test]
    fn mixed_size() {
        run(|| async {
            let small = Fp31::truncate_from(7_u128);
            let large = Fp32BitPrime::truncate_from(5_108_u128);
            let sender = sender();
            let send_small = sender.send(0, small);
            let send_large = sender.send(1, large);
            let close = sender.close(2);
            let close_send = join3(send_small, send_large, close);
            let (_, taken) = join(close_send, sender.as_stream().collect::<Vec<_>>()).await;
            let flat = taken.into_iter().flatten().collect::<Vec<_>>();
            let small_out = Fp31::deserialize(GenericArray::from_slice(&flat[..1]));
            assert_eq!(small_out, small);
            let large_out = Fp32BitPrime::deserialize(GenericArray::from_slice(&flat[1..]));
            assert_eq!(large_out, large);
        });
    }

    #[test]
    fn random_fp32bit() {
        const COUNT: usize = 16;
        const SZ: usize = <<Fp32BitPrime as Serializable>::Size as Unsigned>::USIZE;

        run(|| async {
            let mut rng = thread_rng();
            let mut values = Vec::with_capacity(COUNT);
            values.resize_with(COUNT, || rng.gen::<Fp32BitPrime>());

            let sender = sender();
            let (_, _, output) = join3(
                join_all(values.iter().enumerate().map(|(i, &v)| sender.send(i, v))),
                sender.close(values.len()),
                sender.as_stream().collect::<Vec<_>>(),
            )
            .await;

            let buf = output.into_iter().flatten().collect::<Vec<_>>();
            for (&v, b) in zip(values.iter(), buf.chunks(SZ)) {
                assert_eq!(v, Fp32BitPrime::deserialize(GenericArray::from_slice(b)));
            }
        });
    }

    /// Shuffle `count` indices.
    pub fn shuffle_indices(count: usize) -> Vec<usize> {
        use rand::seq::SliceRandom;
        let mut indices = (0..count).collect::<Vec<_>>();
        indices.shuffle(&mut thread_rng());
        indices
    }

    /// Shuffle the order of sends, which should have no impact.
    #[test]
    fn shuffle_fp31() {
        const COUNT: usize = 16;
        const SZ: usize = <<Fp31 as Serializable>::Size as Unsigned>::USIZE;

        run(|| async {
            let mut rng = thread_rng();
            let mut values = Vec::with_capacity(COUNT);
            values.resize_with(COUNT, || rng.gen::<Fp31>());
            let indices = shuffle_indices(COUNT);

            let sender = sender();
            let (_, _, output) = join3(
                join_all(indices.into_iter().map(|i| sender.send(i, values[i]))),
                sender.close(values.len()),
                sender.as_stream().collect::<Vec<_>>(),
            )
            .await;

            let buf = output.into_iter().flatten().collect::<Vec<_>>();
            for (&v, b) in zip(values.iter(), buf.chunks(SZ)) {
                assert_eq!(v, Fp31::deserialize(GenericArray::from_slice(b)));
            }
        });
    }
}
