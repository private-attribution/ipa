use std::{
    marker::PhantomData,
    mem::take,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{task::Waker, Future, Stream};
use generic_array::GenericArray;
use typenum::Unsigned;

use crate::{
    error::BoxError,
    helpers::Message,
    protocol::RecordId,
    sync::{Arc, Mutex},
};

#[derive(Debug, thiserror::Error)]
#[error("Expected to receive {0:?} but hit end of stream")]
pub struct EndOfStreamError(RecordId);

#[derive(Debug, thiserror::Error)]
#[error("Error deserializing {0:?} record: {1}")]
pub struct DeserializeError(RecordId, BoxError);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    DeserializeFailed(#[from] DeserializeError),
    #[error(transparent)]
    EndOfStream(#[from] EndOfStreamError),
}

/// A future for receiving item `i` from an `UnorderedReceiver`.
pub struct Receiver<S, C, M>
where
    S: Stream<Item = C> + Send,
    C: AsRef<[u8]>,
    M: Message,
{
    i: usize,
    shared_state: Arc<Mutex<OperatingState<S, C>>>,
    _marker: PhantomData<M>,
}

impl<S, C, M> Future for Receiver<S, C, M>
where
    S: Stream<Item = C> + Send,
    C: AsRef<[u8]>,
    M: Message,
{
    type Output = Result<M, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_ref();
        let mut recv = this.shared_state.lock().unwrap();
        if recv.is_next(this.i) {
            recv.poll_next(cx)
        } else {
            recv.add_waker(this.i, cx.waker());
            Poll::Pending
        }
    }
}

/// Saved unread data from a received chunk.
#[derive(Default)]
struct Spare {
    buf: Vec<u8>,
    offset: usize,
}

impl Spare {
    /// Read a message from the buffer.  Returns `None` if there isn't enough data.
    fn read<M: Message>(&mut self) -> Option<Result<M, M::DeserializationError>> {
        let end = self.offset + M::Size::USIZE;
        if end <= self.buf.len() {
            let m = M::deserialize(GenericArray::from_slice(&self.buf[self.offset..end]));
            self.offset = end;
            Some(m)
        } else {
            None
        }
    }

    /// Replace the stored value with the given slice.
    fn replace(&mut self, v: &[u8]) {
        self.offset = 0;
        self.buf.truncate(0);
        self.buf.extend_from_slice(v);
    }

    /// Extend the buffer with new data.
    /// This returns a message if there is enough data.
    /// This returns a value because it can be more efficient in cases where
    /// received chunks don't align with messages.
    fn extend<M: Message>(&mut self, v: &[u8]) -> Option<Result<M, M::DeserializationError>> {
        let sz = <M::Size as Unsigned>::USIZE;
        let remainder = self.buf.len() - self.offset;
        if remainder + v.len() < sz {
            // Not enough data: save it.
            // If we're working from the tail of a longer buffer, only retain the tail.
            self.buf = self.buf.split_off(self.offset);
            self.buf.extend_from_slice(v);
            self.offset = 0;
            return None;
        }

        let m = if remainder > 0 {
            // Copy to the stack to join old and new data.
            let needed = sz - remainder;
            let mut tmp = GenericArray::<u8, M::Size>::default();
            tmp[..remainder].copy_from_slice(&self.buf[self.offset..]);
            tmp[remainder..].copy_from_slice(&v[..needed]);
            self.replace(&v[needed..]);
            M::deserialize(&tmp)
        } else {
            self.replace(&v[sz..]);
            M::deserialize(GenericArray::from_slice(&v[..sz]))
        };
        Some(m)
    }
}

pub struct OperatingState<S, C>
where
    S: Stream<Item = C>,
    C: AsRef<[u8]>,
{
    /// The stream we're reading from.
    stream: Pin<Box<S>>,
    /// The absolute index of the next value that will be received.
    next: usize,
    /// The maximum value that has ever been requested to receive.
    max_polled_idx: Option<usize>,
    /// The underlying stream can provide chunks of data larger than a single
    /// message.  Save any spare data here.
    spare: Spare,
    /// This tracks `Waker` instances from calls to `recv()` with indices that
    /// aren't ready at the time of the call.  If the future is invoked prior
    /// to the value being ready, the `Waker` is saved here.
    wakers: Vec<Option<Waker>>,
    /// If we ever find that a waker doesn't fit in `wakers`, this is where
    /// they are stashed.  These are more than `c` items past the current
    /// item into the future when registered (c = capacity or `wakers.len()`).
    /// So we don't want to wake them frequently.  Instead, these are woken on
    /// a fixed cadence of every `c/2` items.
    ///
    /// When polled again, any that were only a little past the capacity will
    /// be entered into normal `wakers` correctly.  Those that are too far
    /// ahead (i.e., `d = i - (next + c)` is large) they will be woken at most
    /// `2d/c + 1` times extra.
    ///
    /// Assuming that the awoken items are polled in a timely fashion, this
    /// ensures that any overflow will be registered in `wakers` (or read)
    /// before the data needs to be read.  Notifying every `c` items rather
    /// than `c/2` could mean that a task is not able to poll and enter
    /// `wakers` in time to be read out.
    ///
    /// Note: in protocols we try to send before receiving, so we can rely on
    /// that easing load on this mechanism.  There might also need to be some
    /// end-to-end back pressure for tasks that do not involve sending at all.
    ///
    /// If stall detection is enabled, the index of that waker is stored alongside with it, in order
    /// to correctly identify the `i` awaiting completion
    #[cfg(feature = "stall-detection")]
    overflow_wakers: Vec<(Waker, usize)>,
    #[cfg(not(feature = "stall-detection"))]
    overflow_wakers: Vec<Waker>,
    _marker: PhantomData<C>,
}

impl<S, C> OperatingState<S, C>
where
    S: Stream<Item = C> + Send,
    C: AsRef<[u8]>,
{
    /// Determine whether `i` is the next record that we expect to receive.
    fn is_next(&self, i: usize) -> bool {
        i == self.next
    }

    /// Track a waker from a future that was invoked before data was ready.
    ///
    /// # Panics
    ///
    /// If `i` is for an message that has already been read.
    ///
    /// [`recv`]: UnorderedReceiver::recv
    /// [`poll`]: Future::poll
    fn add_waker(&mut self, i: usize, waker: &Waker) {
        assert!(
            i > self.next,
            "Awaiting a read (record = {i}) that has already been fulfilled. Read cursor is currently at {}", self.next
        );
        // We don't save a waker at `self.next`, so `>` and not `>=`.
        if i > self.next + self.wakers.len() {
            #[cfg(feature = "stall-detection")]
            let overflow = (waker.clone(), i);
            #[cfg(not(feature = "stall-detection"))]
            let overflow = waker.clone();
            self.overflow_wakers.push(overflow);
        } else {
            let index = i % self.wakers.len();
            if let Some(old) = self.wakers[index].as_mut() {
                old.clone_from(waker);
            } else {
                self.wakers[index] = Some(waker.clone());
            }
        }
    }

    /// Wake the waker from the next future, if the next receiver has been polled.
    fn wake_next(&mut self) {
        self.next += 1;
        let index = self.next % self.wakers.len();
        if let Some(w) = self.wakers[index].take() {
            w.wake();
        }
        if self.next % (self.wakers.len() / 2) == 0 {
            // Wake all the overflowed wakers.  See comments on `overflow_wakers`.
            #[cfg(feature = "stall-detection")]
            for (w, _) in take(&mut self.overflow_wakers) {
                w.wake();
            }
            #[cfg(not(feature = "stall-detection"))]
            for w in take(&mut self.overflow_wakers) {
                w.wake();
            }
        }
    }

    /// Poll for the next record.  This should only be invoked when
    /// the future for the next message is polled.
    fn poll_next<M: Message>(&mut self, cx: &mut Context<'_>) -> Poll<Result<M, Error>> {
        self.max_polled_idx = std::cmp::max(self.max_polled_idx, Some(self.next));
        if let Some(m) = self.spare.read() {
            self.wake_next();
            return Poll::Ready(m.map_err(|e| DeserializeError::new::<M>(self.next, e).into()));
        }

        loop {
            match self.stream.as_mut().poll_next(cx) {
                Poll::Pending => {
                    return Poll::Pending;
                }
                Poll::Ready(Some(b)) => {
                    let b = b.as_ref();
                    tracing::trace!(len = b.len(), "next chunk");
                    if let Some(m) = self.spare.extend(b) {
                        self.wake_next();
                        return Poll::Ready(
                            m.map_err(|e| DeserializeError::new::<M>(self.next, e).into()),
                        );
                    }
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(EndOfStreamError(RecordId::from(self.next)).into()))
                }
            }
        }
    }

    #[cfg(feature = "stall-detection")]
    fn waiting(&self) -> impl Iterator<Item = usize> + '_ {
        let start = self.next % self.wakers.len();
        self.wakers
            .iter()
            .enumerate()
            .filter_map(|(i, waker)| waker.as_ref().map(|_| i))
            .map(move |i| {
                // We don't save a waker at `self.next`, so `start` is actually the last waker, and
                // `start + 1` is the first.
                if i <= start {
                    self.next + (self.wakers.len() - start + i)
                } else {
                    self.next + (i - start)
                }
            })
            .chain(self.overflow_wakers.iter().map(|v| v.1))
            // include `self.next` if it was ever polled
            .chain(self.max_polled_idx.into_iter().filter(|v| *v == self.next))
    }
}

/// Take an ordered stream of bytes and make messages from that stream
/// available in any order.
pub struct UnorderedReceiver<S, C>
where
    S: Stream<Item = C>,
    C: AsRef<[u8]>,
{
    inner: Arc<Mutex<OperatingState<S, C>>>,
}

impl<S, C> UnorderedReceiver<S, C>
where
    S: Stream<Item = C> + Send,
    C: AsRef<[u8]>,
{
    /// Wrap a stream for unordered reading.
    ///
    /// The capacity here determines how far ahead a read can be.  In most cases,
    /// this should be the same as the value given to `ordering_mpsc`.
    ///
    /// # Panics
    ///
    /// The `capacity` needs to be at least 2.
    pub fn new(stream: Pin<Box<S>>, capacity: NonZeroUsize) -> Self {
        // We use `c/2` as a divisor, so `c == 1` would be bad.
        assert!(capacity.get() > 1, "a capacity of 1 is too small");
        let wakers = vec![None; capacity.get()];
        Self {
            inner: Arc::new(Mutex::new(OperatingState {
                stream,
                next: 0,
                max_polled_idx: None,
                spare: Spare::default(),
                wakers,
                overflow_wakers: Vec::new(),
                _marker: PhantomData,
            })),
        }
    }

    /// Receive from the stream at index `i`.
    ///
    /// # Panics
    ///
    /// Only if there are multiple invocations for the same `i`.
    /// If one future is resolved, the other will panic when polled.
    /// If both futures are polled by different contexts, the second will panic.
    pub fn recv<M: Message, I: Into<usize>>(&self, i: I) -> Receiver<S, C, M> {
        Receiver {
            i: i.into(),
            shared_state: Arc::clone(&self.inner),
            _marker: PhantomData,
        }
    }

    #[cfg(feature = "stall-detection")]
    pub fn waiting(&self) -> Vec<usize> {
        let state = self.inner.lock().unwrap();
        let mut r = state.waiting().collect::<Vec<_>>();

        r.sort_unstable();

        r
    }
}

impl<S, C> Clone for UnorderedReceiver<S, C>
where
    S: Stream<Item = C> + Send,
    C: AsRef<[u8]>,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl DeserializeError {
    pub fn new<M: Message>(next: usize, error: M::DeserializationError) -> Self {
        Self(RecordId::from(next), Box::new(error))
    }
}

#[cfg(all(test, any(unit_test, feature = "shuttle")))]
mod test {
    use std::num::NonZeroUsize;

    use futures::{
        future::{try_join, try_join_all},
        stream::iter,
        Future, Stream,
    };
    use generic_array::GenericArray;
    use rand::Rng;
    #[cfg(feature = "shuttle")]
    use shuttle::future::spawn;
    #[cfg(not(feature = "shuttle"))]
    use tokio::spawn;
    use typenum::Unsigned;

    use crate::{
        ff::{Fp31, Fp32BitPrime, Serializable, U128Conversions},
        helpers::buffers::unordered_receiver::UnorderedReceiver,
    };

    fn receiver<I, T>(it: I) -> UnorderedReceiver<impl Stream<Item = T>, T>
    where
        I: IntoIterator<Item = T> + 'static,
        I::IntoIter: Send,
        T: AsRef<[u8]> + 'static,
    {
        // Use a small capacity so that we can overflow it easily.
        let capacity = NonZeroUsize::new(3).unwrap();
        UnorderedReceiver::new(Box::pin(iter(it)), capacity)
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

    #[test]
    fn three_same() {
        const DATA: &[u8] = &[7, 12, 2];

        run(|| {
            let recv = receiver(vec![DATA.to_vec()]);
            async move {
                try_join_all(DATA.iter().enumerate().map(|(i, &v)| {
                    spawn({
                        let recv = recv.clone();
                        async move {
                            let f: Fp31 = recv.recv(i).await.unwrap();
                            assert_eq!(f, Fp31::try_from(u128::from(v)).unwrap());
                        }
                    })
                }))
                .await
                .unwrap();
            }
        });
    }

    /// Read a one byte value then a four byte value.
    async fn one_then_four(data: &'static [&'static [u8]]) {
        let recv = receiver(data);
        try_join(
            spawn({
                let recv = recv.clone();
                async move {
                    let f: Fp31 = recv.recv(0_usize).await.unwrap();
                    assert_eq!(f, Fp31::try_from(18).unwrap());
                }
            }),
            spawn({
                let recv = recv.clone();
                async move {
                    let f: Fp32BitPrime = recv.recv(1_usize).await.unwrap();
                    assert_eq!(f, Fp32BitPrime::truncate_from(0x0100_020c_u128));
                }
            }),
        )
        .await
        .unwrap();
    }

    /// Provide the values in a single chunk.
    #[test]
    fn different_types() {
        const DATA: &[u8] = &[18, 12, 2, 0, 1];

        run(|| async {
            one_then_four(&[DATA]).await;
        });
    }

    /// Provide values one byte at a time.
    #[test]
    fn byte_by_byte() {
        const DATA: &[&[u8]] = &[&[18], &[12], &[2], &[0], &[1]];

        run(|| async {
            one_then_four(DATA).await;
        });
    }

    /// Encode 10 values and then read them out.
    /// This splits the buffer into three chunks.
    #[test]
    fn random_fp32bit() {
        const COUNT: usize = 16;
        const SZ: usize = <<Fp32BitPrime as Serializable>::Size as Unsigned>::USIZE;
        const ENCODED_LEN: usize = COUNT * SZ;

        run(|| {
            let mut rng = crate::rand::thread_rng();
            let mut values = Vec::with_capacity(COUNT);
            values.resize_with(COUNT, || rng.gen::<Fp32BitPrime>());

            let mut encoded = vec![0; ENCODED_LEN];
            for (i, v) in values.iter().enumerate() {
                let buf = GenericArray::from_mut_slice(&mut encoded[(i * SZ)..((i + 1) * SZ)]);
                v.serialize(buf);
            }

            let mut encoded = encoded.clone();
            let values = values.clone();

            // Split the encoded array into three pieces at random.
            // This is not uniform, but that doesn't matter much.
            let mut rng = crate::rand::thread_rng();
            let cut = rng.gen_range(1..encoded.len() - 1);
            let mut encoded_middle = encoded.split_off(cut);
            let cut = rng.gen_range(1..encoded_middle.len());
            let encoded_end = encoded_middle.split_off(cut);

            let recv = receiver(vec![encoded, encoded_middle, encoded_end]);
            async move {
                try_join_all(values.iter().enumerate().map(|(i, &v)| {
                    spawn({
                        let recv = recv.clone();
                        async move {
                            let f: Fp32BitPrime = recv.recv(i).await.unwrap();
                            assert_eq!(f, v);
                        }
                    })
                }))
                .await
                .unwrap();
            }
        });
    }

    /// Run a synchronous test with all data available from the outset.
    /// Demonstrate that throwing out a future (as `now_or_never` does)
    /// is safe.
    #[test]
    // UnorderedReceiver uses Mutex that gets replaced with Shuttle version of it.
    // The problem here is that this test does not use any async engine, so Shuttle cannot really
    // inject its runtime and this test panics. There is no reason to use Shuttle here.
    #[cfg(not(feature = "shuttle"))]
    fn synchronous() {
        use futures::FutureExt;

        const DATA: &[u8] = &[18, 12];
        let recv = receiver(&[DATA]);
        assert!(recv.recv::<Fp31, _>(1_usize).now_or_never().is_none());
        assert!(recv.recv::<Fp31, _>(1_usize).now_or_never().is_none());
        for (i, &v) in DATA.iter().enumerate() {
            let f: Fp31 = recv.recv(i).now_or_never().unwrap().unwrap();
            assert_eq!(f, Fp31::try_from(u128::from(v)).unwrap());
        }
    }

    /// Register more reads than the receiver has the capacity to track.
    /// Start by registering those that are furthest into the future to
    /// exercise the overflow tracking mechanism.
    #[test]
    fn too_many_reads() {
        const DATA: &[u8] = &[1, 2, 3, 5, 7, 11, 13, 17, 23, 29];
        run(|| {
            let recv = receiver(vec![DATA.to_vec()]);
            async move {
                // True concurrency is needed here.
                try_join_all(DATA.iter().enumerate().rev().map(|(i, &v)| {
                    spawn({
                        let recv = recv.clone();
                        async move {
                            let f: Fp31 = recv.recv(i).await.unwrap();
                            assert_eq!(f, Fp31::try_from(u128::from(v)).unwrap());
                        }
                    })
                }))
                .await
                .unwrap();
            }
        });
    }
}
