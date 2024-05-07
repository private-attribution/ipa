use std::{
    borrow::Borrow,
    cmp::Ordering,
    collections::VecDeque,
    fmt::Debug,
    marker::PhantomData,
    num::NonZeroUsize,
    pin::Pin,
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
    /// The portion of the buffer that is marked "spare". Once `written + spare` is greater than
    /// the buffer capacity, data is available to the stream. May be zero if messages are uniformly
    /// sized and that size divides the buffer capacity.
    spare: usize,
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
    fn new(capacity: NonZeroUsize, spare: usize) -> Self {
        Self {
            buf: vec![0; capacity.get() + spare],
            spare,
            written: 0,
            closed: false,
            write_ready: None,
            stream_ready: None,
        }
    }

    fn save_waker(v: &mut Option<Waker>, cx: &Context<'_>) {
        if let Some(waker) = v {
            waker.clone_from(cx.waker());
        } else {
            v.replace(cx.waker().clone());
        }
    }

    fn wake(v: &mut Option<Waker>) {
        if let Some(w) = v.take() {
            w.wake();
        }
    }

    // See "Spare capacity configuration" in the `OrderingSender` documentation re: `spare` and
    // deadlock avoidance.
    //
    // In the "spare capacity" mode, an assertion in this function could check that every message
    // fits within the spare space, which would catch broken implementations as long as a
    // maximally-sized message is sent during testing.
    //
    // It is harder to prove through assertions and/or static analysis that every message ever
    // sent will be the same size, so we settle for a less strict check that should at least
    // prevent reaching a deadlock.
    fn write<M: Message>(&mut self, m: &M, cx: &Context<'_>) -> Poll<()> {
        debug_assert!(
            self.spare != 0 || self.buf.capacity() % M::Size::USIZE == 0,
            "invalid spare capacity for OrderingSender (see docs)",
        );

        if !self.accept_writes() {
            Self::save_waker(&mut self.write_ready, cx);
            return Poll::Pending;
        }

        let b = &mut self.buf[self.written..];
        assert!(
            M::Size::USIZE <= b.len(),
            "expect message size {:?} to fit in available buffer; only {:?} of {:?} available",
            M::Size::USIZE,
            self.buf.capacity() - self.written,
            self.buf.capacity(),
        );
        self.written += M::Size::USIZE;
        m.serialize(GenericArray::from_mut_slice(&mut b[..M::Size::USIZE]));

        if !self.accept_writes() {
            Self::wake(&mut self.stream_ready);
        }
        Poll::Ready(())
    }

    fn take(&mut self, cx: &Context<'_>) -> Poll<Vec<u8>> {
        if self.written > 0 && (self.written + self.spare >= self.buf.len() || self.closed) {
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

    /// Returns `true` if more writes can be accepted by this sender.
    /// If message size exceeds the remaining capacity, [`write`] may
    /// still return `Poll::Pending` even if sender is open for writes.
    ///
    /// [`write`]: Self::write
    fn accept_writes(&self) -> bool {
        self.written + self.spare < self.buf.len()
    }
}

/// An saved waker for a given index.
#[derive(Debug)]
struct WakerItem {
    /// The index.
    i: usize,
    /// The waker.
    w: Waker,
}

/// A collection of saved wakers.
#[derive(Default, Debug)]
struct WaitingShard {
    /// The maximum index that was used to wake a task that belongs to this shard.
    /// Updates to this shard will be rejected if the supplied index is less than this value.
    /// See [`Add`] for more details.
    ///
    /// [`Add`]: WaitingShard::add
    woken_at: usize,
    /// The saved wakers.  These are sorted on insert (see `add`) and
    /// presumably removed constantly, so a circular buffer is used.
    wakers: VecDeque<WakerItem>,
}

impl WaitingShard {
    /// Add a waker that will be used to wake up a write to `i`.
    ///
    /// ## Errors
    /// If `current` is behind the current position recorded in this shard.
    fn add(&mut self, current: usize, i: usize, w: &Waker) -> Result<(), ()> {
        if current < self.woken_at {
            // this means this thread is out of sync and there was an update to channel's current
            // position. Accepting a waker could mean it will never be awakened. Rejecting this operation
            // will let the current thread to read the position again.
            Err(())?;
        }

        // Each new addition will tend to have a larger index, so search backwards and
        // replace an equal index or insert after a smaller index.
        // TODO: consider a binary search if the item cannot be added to the end.
        let item = WakerItem { i, w: w.clone() };
        for j in (0..self.wakers.len()).rev() {
            match self.wakers[j].i.cmp(&i) {
                Ordering::Greater => (),
                Ordering::Equal => {
                    self.wakers[j] = item;
                    return Ok(());
                }
                Ordering::Less => {
                    self.wakers.insert(j + 1, item);
                    return Ok(());
                }
            }
        }
        self.wakers.insert(0, item);
        Ok(())
    }

    fn wake(&mut self, i: usize) {
        // Waking thread may have lost the race and got the lock after the successful write
        // to the next element. Moving `woken_at` back will introduce a concurrency bug.
        self.woken_at = std::cmp::max(self.woken_at, i);

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

    #[cfg(feature = "stall-detection")]
    pub fn waiting(&self) -> impl Iterator<Item = usize> + '_ {
        self.wakers.iter().map(|waker| waker.i)
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

    /// Add a waker that will be used to wake up a write to `i`.
    ///
    /// ## Errors
    /// If `current` is behind the current position recorded in this shard.
    fn add(&self, current: usize, i: usize, w: &Waker) -> Result<(), ()> {
        self.shard(i).add(current, i, w)
    }

    fn wake(&self, i: usize) {
        self.shard(i).wake(i);
    }

    /// Returns all records currently waiting to be sent in sorted order.
    #[cfg(feature = "stall-detection")]
    fn waiting(&self) -> std::collections::BTreeSet<usize> {
        let mut records = std::collections::BTreeSet::new();
        self.shards
            .iter()
            .for_each(|shard| records.extend(shard.lock().unwrap().waiting()));

        records
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
/// Once `write_size` threshold has been reached, no subsequent writes
/// are allowed, until stream is polled. `OrderingSender` guarantees equal
/// size chunks will be sent to the stream when it is used to buffer
/// same-sized messages.
///
/// # Spare capacity configuration
///
/// `OrderingSender` may be used in two ways:
///  * To send messages of uniform size using a buffer that is a multiple of the message size. In
///    this case, no spare capacity is required.
///  * To send messages of varying size or with a buffer that is not a multiple of the message size.
///    In this case, a deadlock could occur if the data already in the buffer does not reach the
///    threshold for sending but an additional message does not fit. To avoid this, the `spare`
///    capacity must be set at least as large as the largest message.
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
    pub fn new(write_size: NonZeroUsize, spare: usize) -> Self {
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
    /// * the message could result in a deadlock (see [capacity]), or
    /// * the same index is provided more than once.
    ///
    /// [capacity]: OrderingSender#spare-capacity-configuration
    pub fn send<M: Message, B: Borrow<M>>(&self, i: usize, m: B) -> Send<'_, M, B> {
        Send {
            i,
            m,
            sender: self,
            phantom_data: PhantomData,
        }
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

    /// Returns `true` if this sender is closed for writes.
    ///
    /// ## Panics
    /// If the underlying mutex is poisoned or locked by the same thread.
    pub fn is_closed(&self) -> bool {
        self.state.lock().unwrap().closed
    }

    /// Perform the next `send` or `close` operation.
    fn next_op<F>(&self, i: usize, cx: &Context<'_>, f: F) -> Poll<()>
    where
        F: FnOnce(&mut MutexGuard<'_, State>) -> Poll<()>,
    {
        // This load here is on the hot path.
        // Don't acquire the state mutex unless this test passes.
        loop {
            let curr = self.next.load(Acquire);
            match curr.cmp(&i) {
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
                    break res;
                }
                Ordering::Less => {
                    // This is the hot path. Wait our turn. If our view of the world is obsolete
                    // we won't be able to add a waker and need to read the atomic again.
                    //
                    // Here is why it works:
                    // * The only thread updating the atomic is the one that is writing to `i`.
                    // * If the write to `i` is successful, it wakes up the thread waiting to write `i` + 1.
                    // * Adding a waker and waking it is within a critical section.
                    //
                    // There are two possible scenarios for two threads competing for `i` + 1 waker.
                    // * Waiting thread adds a waker before writer thread attempts to wake it. This is a normal case
                    // scenario and things work as expected
                    // * Waiting thread attempts to add a waker after writer tried to wake it. This attempt will
                    // be rejected because writer has moved the waiting shard position ahead and it won't match
                    // the value of `self.next` read by the waiting thread.
                    if self.waiting.add(curr, i, cx.waker()).is_ok() {
                        break Poll::Pending;
                    }
                }
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
    #[cfg(all(test, any(unit_test, feature = "shuttle")))]
    fn as_stream(&self) -> OrderedStream<&Self> {
        OrderedStream { sender: self }
    }

    #[cfg(all(test, unit_test))]
    pub(crate) fn as_rc_stream(
        self: crate::sync::Arc<Self>,
    ) -> OrderedStream<crate::sync::Arc<Self>> {
        OrderedStream { sender: self }
    }

    /// This returns a set of record indices waiting to be sent.
    ///
    /// ## Panics
    /// If state mutex is poisoned.
    #[cfg(feature = "stall-detection")]
    pub fn waiting(&self) -> std::collections::BTreeSet<usize> {
        use crate::sync::atomic::Ordering::Relaxed;

        let mut waiting_indices = self.waiting.waiting();
        let state = self.state.lock().unwrap();
        if state.write_ready.is_some() {
            waiting_indices.insert(self.next.load(Relaxed));
        }

        waiting_indices
    }
}

/// A future for writing item `i` into an `OrderingSender`.
pub struct Send<'a, M: Message, B: Borrow<M> + 'a> {
    i: usize,
    m: B,
    sender: &'a OrderingSender,
    phantom_data: PhantomData<M>,
}

impl<'a, M: Message, B: Borrow<M> + 'a> Future for Send<'a, M, B> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut();

        let res = this.sender.next_op(this.i, cx, |b| {
            assert!(!b.closed, "writing on a closed stream");
            b.write(this.m.borrow(), cx)
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
    use std::{
        future::poll_fn,
        iter::zip,
        num::NonZeroUsize,
        pin::{pin, Pin},
    };

    use futures::{
        future::{join, join3, join_all, poll_immediate, try_join_all},
        stream::StreamExt,
        Future, FutureExt,
    };
    use generic_array::GenericArray;
    use rand::{seq::SliceRandom, Rng};
    #[cfg(feature = "shuttle")]
    use shuttle::future as tokio;
    use typenum::Unsigned;

    use super::OrderingSender;
    use crate::{
        ff::{Fp31, Fp32BitPrime, Gf20Bit, Gf9Bit, Serializable, U128Conversions},
        helpers::MpcMessage,
        rand::thread_rng,
        sync::Arc,
        test_executor::run,
    };

    fn sender() -> Arc<OrderingSender> {
        Arc::new(OrderingSender::new(NonZeroUsize::new(6).unwrap(), 5))
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
            let output = Fp31::deserialize_unchecked(GenericArray::from_slice(&flat));
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
            let output = Fp31::deserialize_unchecked(GenericArray::from_slice(&flat));
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

    type BoxedSendFn = Box<
        dyn for<'a> FnOnce(
            &'a OrderingSender,
            &mut usize,
        ) -> Pin<Box<dyn Future<Output = ()> + 'a>>,
    >;

    // Given a message, returns a closure that sends the message and increments an associated record index.
    fn send_fn<M: MpcMessage>(m: M) -> BoxedSendFn {
        Box::new(|s: &OrderingSender, i: &mut usize| {
            let fut = s.send(*i, m).boxed();
            *i += 1;
            fut
        })
    }

    #[test]
    fn spare_config() {
        const SZ: usize = <<Fp32BitPrime as Serializable>::Size as Unsigned>::USIZE;
        run(|| async {
            const COUNT: usize = 4;
            const CAPACITY: usize = COUNT * SZ;

            // Case 1: Sending equal sized records with no spare capacity
            let sender = OrderingSender::new(CAPACITY.try_into().unwrap(), 0);

            for i in 0..COUNT {
                sender
                    .send(i, Fp32BitPrime::truncate_from(u128::try_from(i).unwrap()))
                    .await;
            }

            // buffer is now full.
            let mut f = pin!(sender.send(
                COUNT,
                Fp32BitPrime::truncate_from(u128::try_from(COUNT).unwrap())
            ));
            assert_eq!(None, poll_immediate(&mut f).await);

            drop(poll_fn(|ctx| sender.take_next(ctx)).await);

            // now we can send again.
            assert_eq!(Some(()), poll_immediate(f).await);

            for i in (COUNT + 1)..(2 * COUNT) {
                sender
                    .send(i, Fp32BitPrime::truncate_from(u128::try_from(i).unwrap()))
                    .await;
            }

            // spare has enough capacity, but buffer is considered full.
            let mut f = pin!(sender.send(2 * COUNT, Fp32BitPrime::truncate_from(2_u128)));
            assert_eq!(None, poll_immediate(&mut f).await);

            // Case 2: Sending unequal sized records with sufficient spare capacity
            let sender = OrderingSender::new(CAPACITY.try_into().unwrap(), 4);

            let mut messages = vec![
                send_fn(Fp32BitPrime::truncate_from(400_u128)),
                send_fn(Fp32BitPrime::truncate_from(401_u128)),
                send_fn(Gf20Bit::truncate_from(302_u128)),
                send_fn(Gf20Bit::truncate_from(303_u128)),
                send_fn(Gf9Bit::truncate_from(204_u128)),
            ];
            messages.shuffle(&mut thread_rng());

            let mut i = 0;
            for send_fn in messages {
                (send_fn)(&sender, &mut i).await;
            }

            // spare has enough capacity, but buffer is considered full.
            let mut f = pin!(sender.send(i, Fp32BitPrime::truncate_from(2_u128)));
            assert_eq!(None, poll_immediate(&mut f).await);

            drop(poll_fn(|ctx| sender.take_next(ctx)).await);
            assert_eq!(Some(()), poll_immediate(f).await);
        });
    }

    #[test]
    #[should_panic(
        expected = "expect message size 4 to fit in available buffer; only 2 of 16 available"
    )]
    fn invalid_no_spare() {
        run(|| async {
            // Sending unequal size messages with no spare capacity is invalid.
            let sender = OrderingSender::new(16.try_into().unwrap(), 0);

            let messages = vec![
                send_fn(Fp32BitPrime::truncate_from(400_u128)),
                send_fn(Fp32BitPrime::truncate_from(401_u128)),
                send_fn(Gf9Bit::truncate_from(202_u128)),
                send_fn(Fp32BitPrime::truncate_from(403_u128)),
                send_fn(Fp32BitPrime::truncate_from(404_u128)),
            ];

            let mut i = 0;
            for send_fn in messages {
                (send_fn)(&sender, &mut i).await;
            }
        });
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "invalid spare capacity for OrderingSender (see docs)")]
    fn invalid_no_spare_assertion() {
        run(|| async {
            // When there is no spare capacity, the message size must divide the capacity.
            let sender = OrderingSender::new(16.try_into().unwrap(), 0);
            sender.send(0, Gf20Bit::truncate_from(0_u128)).await;
        });
    }

    #[test]
    #[should_panic(
        expected = "expect message size 4 to fit in available buffer; only 3 of 18 available"
    )]
    fn insufficient_spare() {
        run(|| async {
            // When messages sizes are not uniform, the spare capacity must fit the largest message.
            let sender = OrderingSender::new(16.try_into().unwrap(), 2);

            let messages = vec![
                send_fn(Fp32BitPrime::truncate_from(400_u128)),
                send_fn(Gf20Bit::truncate_from(301_u128)),
                send_fn(Fp32BitPrime::truncate_from(402_u128)),
                send_fn(Fp32BitPrime::truncate_from(403_u128)),
                send_fn(Fp32BitPrime::truncate_from(404_u128)),
            ];

            let mut i = 0;
            for send_fn in messages {
                (send_fn)(&sender, &mut i).await;
            }
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
            let small_out = Fp31::deserialize_unchecked(GenericArray::from_slice(&flat[..1]));
            assert_eq!(small_out, small);
            let large_out =
                Fp32BitPrime::deserialize_unchecked(GenericArray::from_slice(&flat[1..]));
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
            let (_, (), output) = join3(
                join_all(values.iter().enumerate().map(|(i, &v)| sender.send(i, v))),
                sender.close(values.len()),
                sender.as_stream().collect::<Vec<_>>(),
            )
            .await;

            let buf = output.into_iter().flatten().collect::<Vec<_>>();
            for (&v, b) in zip(values.iter(), buf.chunks(SZ)) {
                assert_eq!(
                    v,
                    Fp32BitPrime::deserialize_unchecked(GenericArray::from_slice(b))
                );
            }
        });
    }

    /// Shuffle `count` indices.
    pub fn shuffle_indices(count: usize) -> Vec<usize> {
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
            let (_, (), output) = join3(
                join_all(indices.into_iter().map(|i| sender.send(i, values[i]))),
                sender.close(values.len()),
                sender.as_stream().collect::<Vec<_>>(),
            )
            .await;

            let buf = output.into_iter().flatten().collect::<Vec<_>>();
            for (&v, b) in zip(values.iter(), buf.chunks(SZ)) {
                assert_eq!(v, Fp31::deserialize_unchecked(GenericArray::from_slice(b)));
            }
        });
    }

    /// This test is supposed to eventually hang if there is a concurrency bug inside `OrderingSender`.
    #[test]
    fn parallel_send() {
        const PARALLELISM: usize = 100;

        run(|| async {
            let sender = Arc::new(OrderingSender::new(
                NonZeroUsize::new(PARALLELISM * <Fp31 as Serializable>::Size::USIZE).unwrap(),
                5,
            ));

            try_join_all((0..PARALLELISM).map(|i| {
                tokio::spawn({
                    let sender = Arc::clone(&sender);
                    async move {
                        sender.send(i, Fp31::truncate_from(i as u128)).await;
                    }
                })
            }))
            .await
            .unwrap();
        });
    }

    /// If sender is at capacity, but still have some bytes inside spare, we block the sends
    /// until the stream is flushed. That ensures `OrderingSender` yields the equal-sized
    /// chunks.
    ///
    /// This behavior is important for channels working in parallel `[parallel_join]` and wrapped
    /// inside a windowed execution [`seq_join`]. Not enforcing this leads to some channels moving
    /// forward faster and eventually getting outside of active work window. See [`issue`] for
    /// more details.
    ///
    /// [`seq_join`]: crate::seq_join::SeqJoin::try_join
    /// [`parallel_join`]: crate::seq_join::SeqJoin::parallel_join
    /// [`issue`]: https://github.com/private-attribution/ipa/issues/843
    #[test]
    fn reader_blocks_writers() {
        const SZ: usize = <<Fp32BitPrime as Serializable>::Size as Unsigned>::USIZE;
        run(|| async {
            const CAPACITY: usize = SZ + 1;
            const SPARE: usize = 2 * SZ;
            let sender = OrderingSender::new(CAPACITY.try_into().unwrap(), SPARE);

            // enough bytes in the buffer to hold 2 items
            for i in 0..2 {
                sender
                    .send(i, Fp32BitPrime::truncate_from(u128::try_from(i).unwrap()))
                    .await;
            }

            // spare has enough capacity, but buffer is considered full.
            let mut f = pin!(sender.send(2, Fp32BitPrime::truncate_from(2_u128)));
            assert_eq!(None, poll_immediate(&mut f).await);

            drop(poll_fn(|ctx| sender.take_next(ctx)).await);
            assert_eq!(Some(()), poll_immediate(f).await);
        });
    }
}
