use crate::helpers::messaging::Message;
use futures::{task::Waker, Future, Stream};
use generic_array::GenericArray;
use std::{
    cmp::Ordering,
    collections::VecDeque,
    mem::drop,
    num::NonZeroUsize,
    ops::Deref,
    pin::Pin,
    sync::{
        atomic::{
            AtomicUsize,
            Ordering::{AcqRel, Acquire},
        },
        Mutex, MutexGuard,
    },
    task::{Context, Poll},
};
use typenum::Unsigned;

/// The operating state for an `OrderingSender`.
struct State {
    /// A store of bytes to write into.
    buf: Vec<u8>,
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
    fn new(capacity: NonZeroUsize) -> Self {
        Self {
            buf: vec![0; capacity.get()],
            written: 0,
            closed: false,
            write_ready: None,
            stream_ready: None,
        }
    }

    fn save_waker(v: &mut Option<Waker>, cx: &Context<'_>) {
        if let Some(w) = v.replace(cx.waker().clone()) {
            assert!(cx.waker().will_wake(&w));
        }
    }

    fn wake(v: &mut Option<Waker>) {
        if let Some(w) = v.take() {
            w.wake();
        }
    }

    fn write<M: Message>(&mut self, m: &M, cx: &Context<'_>) -> bool {
        let b = &mut self.buf[self.written..];
        if M::Size::USIZE <= b.len() {
            self.written += M::Size::USIZE;
            m.serialize(GenericArray::from_mut_slice(&mut b[..M::Size::USIZE]));

            if self.written * 2 >= self.buf.len() {
                Self::wake(&mut self.stream_ready);
            }
            true
        } else {
            Self::save_waker(&mut self.write_ready, cx);
            false
        }
    }

    fn take(&mut self, cx: &Context<'_>) -> Option<Vec<u8>> {
        if self.written > 0 && (self.written * 2 >= self.buf.len() || self.closed) {
            let v = self.buf[..self.written].to_vec();
            self.written = 0;

            Self::wake(&mut self.write_ready);
            Some(v)
        } else {
            Self::save_waker(&mut self.stream_ready, cx);
            None
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
                    println!("update waker {i}@{j}");
                    self.wakers[j] = item;
                    return;
                }
                Ordering::Less => {
                    println!("add waker {i}@{j}");
                    self.wakers.insert(j + 1, item);
                    return;
                }
            }
        }
        println!("add waker {i}@0");
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
            println!("wake {i}");
            self.wakers.pop_front().unwrap().w.wake();
        }
    }
}

const NUM_SHARDS: usize = 8;

/// A collection of wakers that are indexed by the send index (`i`).
/// This structure aims to reduce mutex contention by including a number of shards.
#[derive(Default)]
struct Waiting {
    shards: [Mutex<WaitingShard>; NUM_SHARDS],
}

impl Waiting {
    fn add(&self, i: usize, w: Waker) {
        self.shards[i % NUM_SHARDS].lock().unwrap().add(i, w);
    }

    fn wake(&self, i: usize) {
        self.shards[i % NUM_SHARDS].lock().unwrap().wake(i);
    }
}

/// An `OrderingSender` accepts messages for sending in any order, but
/// ensures that they are serialized based on an index.
///
/// # Performance
/// It is recommended that the capacity of the buffer is set to
/// double the number of bytes you want to have transmitted at a time.
/// Data is made available to the output stream once **half** of the
/// capacity has been written.
///
/// Data less than this threshold only becomes available to the stream
/// when the sender is closed (with [`close`]).
///
/// If the messages that are passed to [`send`] are large relative to
/// the capacity, you might need to increase the capacity accordingly
/// so that multiple messages can be accepted.
///
/// [`new`]: OrderingSender::new
/// [`send`]: OrderingSender::send
/// [`close`]: OrderingSender::close
struct OrderingSender {
    next: AtomicUsize,
    state: Mutex<State>,
    waiting: Waiting,
}

impl OrderingSender {
    /// Make an `OrderingSender` with a capacity of `capacity` (in bytes).
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            next: AtomicUsize::new(0),
            state: Mutex::new(State::new(capacity)),
            waiting: Waiting::default(),
        }
    }

    /// Send a message, `m`, at the index `i`.  
    /// This method blocks until all previous messages are sent and until sufficient
    /// space becomes available in the sender's buffer.
    ///
    /// # Panics
    /// Polling the future this method returns will panic if
    /// * the message is too large for the buffer, or
    /// * the same index is provided more than once.
    pub fn send<M: Message>(&self, i: usize, m: M) -> Send<'_, M> {
        println!("send {i}");
        Send { i, m, sender: self }
    }

    /// Close the sender at index `i`.
    /// This method blocks until all previous messages are sent.
    ///
    /// # Panics
    /// Polling the future this method returns will panic if a message has already
    /// been sent with an equal or higher index.
    pub fn close(&self, i: usize) -> Close<'_> {
        println!("send {i}");
        Close { i, sender: self }
    }

    /// Perform the next `send` or `close` operation.
    fn next_op<F>(&self, i: usize, cx: &Context<'_>, f: F) -> Poll<()>
    where
        F: FnOnce(&mut MutexGuard<'_, State>) -> Poll<()>,
    {
        // This load here is on the hot path.
        // Don't acquire the state mutex unless this test passes.
        let next = self.next.load(Acquire);
        println!("next_op {i} / {next}");
        match next.cmp(&i) {
            // match self.next.load(Acquire).cmp(&i) {
            Ordering::Greater => {
                panic!("attempt to write/close at index {i} twice");
            }
            Ordering::Equal => {
                // OK, now it is our turn, so we need to hold a lock.
                // No one else should be incrementing this atomic, so
                // there should be no contention on this lock except for
                // any calls to `take()`, which is fine.
                let mut b = self.state.lock().unwrap();
                let res = f(&mut b);
                if res.is_ready() {
                    let curr = self.next.fetch_add(1, AcqRel);
                    debug_assert_eq!(i, curr, "we just checked this");
                }
                res
            }
            Ordering::Less => {
                // This is the hot path. Wait our turn.
                println!("next_op {i} wait");
                self.waiting.add(i, cx.waker().clone());
                Poll::Pending
            }
        }
    }

    /// Take the next chunk of data that the sender has produced.
    /// This function implements most of what `OrderedStream` needs.
    fn take_next(&self, cx: &Context<'_>) -> Poll<Option<Vec<u8>>> {
        let mut b = self.state.lock().unwrap();

        let v = b.take(cx);
        if let Some(v) = v {
            self.waiting.wake(self.next.load(Acquire));
            println!("read {el}", el = v.len());
            Poll::Ready(Some(v))
        } else if b.closed {
            println!("read close");
            Poll::Ready(None)
        } else {
            // `b.take()` will have tracked the waker
            Poll::Pending
        }
    }

    /// The stream interface requires a mutable reference to the stream itself.
    /// That's not possible here as we create a ton of immutable references to this.
    /// This wrapper takes a trivial reference so that we can implement `Stream`.
    fn as_stream(&self) -> OrderedStream<'_> {
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
            if b.write(&this.m, cx) {
                println!("sent {i}", i = this.i);
                Poll::Ready(())
            } else {
                // Writing is blocked because there is no space.  b.write() saves the waker.
                Poll::Pending
            }
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
struct OrderedStream<'s> {
    sender: &'s OrderingSender,
}

impl<'s> Stream for OrderedStream<'s> {
    type Item = Vec<u8>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        println!("poll stream");
        Pin::get_mut(self).sender.take_next(cx)
    }
}

impl<'s> Deref for OrderedStream<'s> {
    type Target = OrderingSender;
    fn deref(&self) -> &Self::Target {
        self.sender
    }
}

#[cfg(test)]
mod test {
    use super::OrderingSender;
    use crate::{
        bits::Serializable,
        ff::{Fp31, Fp32BitPrime},
        rand::thread_rng,
    };
    use futures::{
        future::{join, join3, join_all},
        stream::StreamExt,
        Future, FutureExt,
    };
    use generic_array::GenericArray;
    use rand::Rng;
    use std::{iter::zip, num::NonZeroUsize};
    use typenum::Unsigned;

    // #[cfg(feature = "shuttle")]
    // use shuttle::future::spawn;
    // #[cfg(not(feature = "shuttle"))]
    // use tokio::spawn;

    fn sender() -> OrderingSender {
        OrderingSender::new(NonZeroUsize::new(11).unwrap())
    }

    #[cfg(not(feature = "shuttle"))]
    fn run<F, Fut>(f: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()>,
    {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f());
    }

    #[cfg(feature = "shuttle")]
    fn run<F, Fut>(f: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()>,
    {
        shuttle::check_random(move || shuttle::future::block_on(f()), 32);
    }

    /// Writing a single value cannot be read until the stream closes.
    #[test]
    fn send_recv() {
        run(|| async {
            let input = Fp31::from(7_u128);
            let sender = sender();
            sender.send(0, input).await;
            assert!(sender.as_stream().next().now_or_never().is_none());
        });
    }

    /// Generate a send and close the stream.
    #[test]
    fn send_close_recv() {
        run(|| async {
            let input = Fp31::from(7_u128);
            let sender = sender();
            let send = sender.send(0, input);
            let close = sender.close(1);
            let send_close = join(send, close);
            let (_, taken) = join(send_close, sender.as_stream().collect::<Vec<_>>()).await;
            let flat = taken.into_iter().flatten().collect::<Vec<_>>();
            let output = Fp31::deserialize(GenericArray::from_slice(&flat));
            assert_eq!(input, output);
        });
    }

    /// Initiate a close before sending.
    #[test]
    fn close_send_recv() {
        run(|| async {
            let input = Fp31::from(7_u128);
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
            let send_many = join_all((0..3_u8).map(|i| sender.send(usize::from(i), Fp31::from(i))));
            let send_again = sender.send(2, Fp31::from(2_u128));
            join(send_many, send_again).await;
        });
    }

    /// Messages can be any size.  The sender doesn't care.
    #[test]
    fn mixed_size() {
        run(|| async {
            let small = Fp31::from(7_u128);
            let large = Fp32BitPrime::from(5_108_u128);
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
