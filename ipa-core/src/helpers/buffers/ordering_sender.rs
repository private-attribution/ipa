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

use crate::{
    helpers::{buffers::circular::CircularBuf, Message},
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
    buf: CircularBuf,
    /// An entity to wake when the buffer is read from.
    write_ready: Option<Waker>,
    /// Another entity to wake when the buffer is read from.
    stream_ready: Option<Waker>,
}

impl State {
    fn new(capacity: usize, write_size: usize, read_threshold: usize) -> Self {
        Self {
            buf: CircularBuf::new(capacity, write_size, read_threshold),
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
        if !self.buf.can_write() {
            Self::save_waker(&mut self.write_ready, cx);
            return Poll::Pending;
        }

        self.buf.next().write(m);

        if self.buf.can_read() {
            Self::wake(&mut self.stream_ready);
        }

        Poll::Ready(())
    }

    fn take(&mut self, cx: &Context<'_>) -> Poll<Vec<u8>> {
        if self.buf.can_read() {
            let can_write = self.buf.can_write();
            let next = self.buf.take();

            if !can_write {
                // We are ready to unblock writers by taking some data that we know is there off
                // the buffer
                Self::wake(&mut self.write_ready);
            }

            Poll::Ready(next)
        } else {
            Self::save_waker(&mut self.stream_ready, cx);
            Poll::Pending
        }
    }

    fn close(&mut self) {
        self.buf.close();
        Self::wake(&mut self.stream_ready);
    }

    fn is_closed(&self) -> bool {
        self.buf.is_closed()
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
    /// Only writes of `write_size` (in bytes) are allowed to this sender.
    /// Reading from it yields `read_threshold` bytes, unless it is closed.
    #[must_use]
    pub fn new(
        capacity: NonZeroUsize,
        write_size: NonZeroUsize,
        read_threshold: NonZeroUsize,
    ) -> Self {
        Self {
            next: AtomicUsize::new(0),
            state: Mutex::new(State::new(
                capacity.get(),
                write_size.get(),
                read_threshold.get(),
            )),
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
        self.state.lock().unwrap().is_closed()
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
            let next = self.next.load(Acquire);
            tracing::trace!(
                closed = b.is_closed(),
                next = next,
                len = v.len(),
                "take_next ready"
            );
            self.waiting.wake(next);
            Poll::Ready(Some(v))
        } else if b.is_closed() {
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
            assert!(!b.is_closed(), "writing on a closed stream");
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

impl Future for Close<'_> {
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

    use ::tokio::sync::Barrier;
    use futures::{
        future::{join, join3, join_all, poll_immediate, try_join_all},
        stream::StreamExt,
        Future, FutureExt,
    };
    use futures_util::future::try_join;
    use generic_array::GenericArray;
    use rand::{seq::SliceRandom, Rng};
    #[cfg(feature = "shuttle")]
    use shuttle::future as tokio;
    use typenum::Unsigned;

    use super::OrderingSender;
    use crate::{
        ff::{Fp31, Fp32BitPrime, Gf9Bit, PrimeField, Serializable, U128Conversions},
        helpers::MpcMessage,
        secret_sharing::SharedValue,
        sync::Arc,
        test_executor::{run, run_random},
    };

    fn sender<F: PrimeField>() -> Arc<OrderingSender> {
        let capacity = NonZeroUsize::new(6 * F::Size::USIZE).unwrap();
        Arc::new(OrderingSender::new(
            capacity,
            NonZeroUsize::new(F::Size::USIZE).unwrap(),
            capacity,
        ))
    }

    /// Writing a single value cannot be read until the stream closes.
    #[test]
    fn send_recv() {
        run(|| async {
            let input = Fp31::truncate_from(7_u128);
            let sender = sender::<Fp31>();
            sender.send(0, input).await;
            assert!(sender.as_stream().next().now_or_never().is_none());
        });
    }

    /// Generate a send and close the stream.
    #[test]
    fn send_close_recv() {
        run(|| async {
            let input = Fp31::truncate_from(7_u128);
            let sender = sender::<Fp31>();
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
            let sender = sender::<Fp31>();
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
            let sender = sender::<Fp31>();
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
            let sender = sender::<Fp31>();
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
            let sender = sender::<Fp31>();
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
    fn full_read_open() {
        const SZ: usize = <<Fp32BitPrime as Serializable>::Size as Unsigned>::USIZE;
        run(|| async {
            const COUNT: usize = 4;
            const CAPACITY: usize = COUNT * SZ;

            let sender = OrderingSender::new(
                CAPACITY.try_into().unwrap(),
                SZ.try_into().unwrap(),
                CAPACITY.try_into().unwrap(),
            );

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
        });
    }

    #[test]
    #[should_panic(expected = "Expect to keep messages of size 4, got 2")]
    fn invalid_uneven_size() {
        run(|| async {
            // Sending unequal size messages is invalid.
            let sender = OrderingSender::new(
                16.try_into().unwrap(),
                4.try_into().unwrap(),
                16.try_into().unwrap(),
            );

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
    #[should_panic(expected = "Expect to keep messages of size 4, got 3")]
    fn invalid_write_size_assertion() {
        run(|| async {
            // The message size must divide the capacity.
            let sender = OrderingSender::new(
                16.try_into().unwrap(),
                4.try_into().unwrap(),
                16.try_into().unwrap(),
            );
            sender
                .send(0, crate::ff::Gf20Bit::truncate_from(0_u128))
                .await;
        });
    }

    /// Shuffle `count` indices.
    pub fn shuffle_indices(count: usize, rng: &mut impl Rng) -> Vec<usize> {
        let mut indices = (0..count).collect::<Vec<_>>();
        indices.shuffle(rng);
        indices
    }

    /// Shuffle the order of sends, which should have no impact.
    #[test]
    fn shuffle_fp31() {
        const COUNT: usize = 16;
        const SZ: usize = <<Fp31 as Serializable>::Size as Unsigned>::USIZE;

        run_random(|mut rng| async move {
            let mut values = Vec::with_capacity(COUNT);
            values.resize_with(COUNT, || rng.gen::<Fp31>());
            let indices = shuffle_indices(COUNT, &mut rng);

            let sender = sender::<Fp31>();
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
            let capacity =
                NonZeroUsize::new(PARALLELISM * <Fp31 as Serializable>::Size::USIZE).unwrap();
            let sender = Arc::new(OrderingSender::new(
                capacity,
                <Fp31 as Serializable>::Size::USIZE.try_into().unwrap(),
                capacity,
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

    /// Make sure writers, when awakened, get the correct state. Currently, mutex used inside the
    /// sender prevents seeing inconsistent results, but if it were ever removed, waking up writer
    /// may lead to it going to sleep again because `take()` hasn't been called yet
    #[test]
    fn take_wake_race() {
        run(|| async {
            let sender = sender::<Fp31>();
            let read_barrier = Arc::new(Barrier::new(2));
            let write_barrier = Arc::new(Barrier::new(2));

            // field size is one byte, so capacity in bytes is equal to capacity in units
            let capacity = sender.state.lock().unwrap().buf.capacity();
            let read_task = tokio::spawn({
                let sender = Arc::clone(&sender);
                let read_barrier = Arc::clone(&read_barrier);
                let write_barrier = Arc::clone(&write_barrier);

                async move {
                    read_barrier.wait().await;
                    let mut stream = sender.as_stream();
                    let Some(next) = stream.next().await else {
                        panic!("Stream is empty")
                    };
                    write_barrier.wait().await;

                    assert_eq!(capacity, next.len());
                }
            });

            let write_task = tokio::spawn({
                let sender = Arc::clone(&sender);
                async move {
                    let _ = join_all((0..capacity).map(|i| sender.send(i, Fp31::ZERO))).await;
                    let mut f = pin!(sender.send(capacity, Fp31::ZERO));

                    assert_eq!(poll_immediate(&mut f).await, None);
                    read_barrier.wait().await;
                    write_barrier.wait().await;
                    // f should be resolved if `take` is implemented correctly.
                    assert_eq!(poll_immediate(f).await, Some(()));
                }
            });

            try_join(read_task, write_task).await.unwrap();
        });
    }

    mod prop_test {
        use std::{cmp::min, iter::zip};

        use futures::{
            future::{join3, join_all},
            stream::StreamExt,
        };
        use generic_array::GenericArray;
        use proptest::{
            arbitrary::any,
            proptest,
            strategy::{Just, Strategy},
        };
        use rand::{
            distributions::{Distribution, Standard},
            rngs::StdRng,
            Rng,
        };
        use rand_core::SeedableRng;
        use typenum::Unsigned;

        use crate::{
            ff::{
                boolean_array::{BA112, BA256, BA7},
                Fp31, Fp32BitPrime, Serializable,
            },
            helpers::OrderingSender,
            secret_sharing::SharedValue,
            test_executor::run,
        };

        async fn random_field<V>(
            count: usize,
            capacity_units: usize,
            read_size_units: usize,
            seed: u64,
        ) where
            V: SharedValue,
            Standard: Distribution<V>,
        {
            assert!(capacity_units >= count && capacity_units >= read_size_units);

            let sz = <V as Serializable>::Size::USIZE;
            let read_size_bytes = sz * read_size_units;

            let mut rng = StdRng::seed_from_u64(seed);
            let mut values = Vec::with_capacity(count);
            values.resize_with(count, || rng.gen::<V>());

            let sender = OrderingSender::new(
                (sz * capacity_units).try_into().unwrap(),
                sz.try_into().unwrap(),
                read_size_bytes.try_into().unwrap(),
            );

            let (_, (), output) = join3(
                join_all(values.iter().enumerate().map(|(i, &v)| sender.send(i, v))),
                sender.close(values.len()),
                sender.as_stream().collect::<Vec<_>>(),
            )
            .await;

            // check output chunks - all except the last one must have the exact size equal to
            // read_size
            let lengths = output.iter().map(Vec::len).collect::<Vec<_>>();
            let read_size_bytes = min(read_size_bytes, sz * count);
            assert!(lengths.len() <= 2);
            assert!(lengths.iter().any(|l| read_size_bytes == *l),
                    "read size {read_size_bytes} chunks never read from OrderingSender. Actual chunks read: {lengths:?}");
            let buf = output.into_iter().flatten().collect::<Vec<_>>();
            for (&v, b) in zip(values.iter(), buf.chunks(sz)) {
                assert_eq!(v, V::deserialize(GenericArray::from_slice(b)).unwrap());
            }
        }

        fn arb_sender_size(max_count: usize) -> impl Strategy<Value = (usize, usize, usize)> {
            (1..=max_count)
                .prop_flat_map(move |count| (Just(count), count..=max_count))
                .prop_flat_map(move |(count, capacity_units)| {
                    (Just(count), Just(capacity_units), count..=capacity_units)
                })
        }

        proptest! {
            #[test]
            fn random_fp31((count, capacity, read_size) in arb_sender_size(99), seed in any::<u64>()) {
                run(move || async move { random_field::<Fp31>(count, capacity, read_size, seed).await });
            }

            #[test]
            fn random_fp32bit((count, capacity, read_size) in arb_sender_size(81), seed in any::<u64>()) {
                run(move || async move { random_field::<Fp32BitPrime>(count, capacity, read_size, seed).await });
            }

            #[test]
            fn random_ba256((count, capacity, read_size) in arb_sender_size(61), seed in any::<u64>()) {
                run(move || async move { random_field::<BA256>(count, capacity, read_size, seed).await });
            }

            #[test]
            fn random_ba112((count, capacity, read_size) in arb_sender_size(94), seed in any::<u64>()) {
                run(move || async move { random_field::<BA112>(count, capacity, read_size, seed).await });
            }

            #[test]
            fn random_ba7((count, capacity, read_size) in arb_sender_size(194), seed in any::<u64>()) {
                run(move || async move { random_field::<BA7>(count, capacity, read_size, seed).await });
            }
        }
    }
}
