use crate::{
    helpers::{messaging::Message, Error},
    protocol::RecordId,
};
use futures::{task::Waker, Future, Stream};
use generic_array::GenericArray;
use pin_project::pin_project;
use std::{
    marker::PhantomData,
    num::NonZeroUsize,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use typenum::Unsigned;

/// A future for receiving item `i` from an `UnorderedReceiver`.
#[pin_project]
pub struct Receiver<S, C, M>
where
    S: Stream<Item = C>,
    C: AsRef<[u8]>,
    M: Message,
{
    #[pin]
    i: usize,
    #[pin]
    receiver: Arc<Mutex<OperatingState<S, C>>>,
    _marker: PhantomData<M>,
}

impl<S, C, M> Future for Receiver<S, C, M>
where
    S: Stream<Item = C>,
    C: AsRef<[u8]>,
    M: Message,
{
    type Output = Result<M, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_ref().project_ref();

        let mut recv = this.receiver.lock().unwrap();
        if recv.is_next(*this.i) {
            recv.poll_next(cx)
        } else {
            recv.add_waker(*this.i, cx.waker().clone());
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
    fn read<M: Message>(&mut self) -> Option<M> {
        println!("Read {} bytes", M::Size::USIZE);
        let end = self.offset + M::Size::USIZE;
        if end <= self.buf.len() {
            let m = M::deserialize(GenericArray::from_slice(&self.buf[self.offset..end]));
            self.offset = end;
            Some(m)
        } else {
            None
        }
    }

    /// Extend the buffer with new data.  
    /// This returns a message if there is enough data.
    /// This returns a value because it can be more efficient in cases where
    /// received chunks don't align with messages.
    fn extend<M: Message>(&mut self, v: &[u8]) -> Option<M> {
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
            self.buf = v[needed..].to_vec();
            M::deserialize(&tmp)
        } else {
            self.buf = v[sz..].to_vec();
            M::deserialize(GenericArray::from_slice(&v[..sz]))
        };
        self.offset = 0;
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
    /// `1 + 2d/c` times extra.
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
    overflow_wakers: Vec<Waker>,
    /// Left over data from a previous `recv()` call.  The underlying stream
    /// can provide chunks of data larger than a single message.  We save the
    /// spare data here.
    spare: Spare,
    /// The absolute index of the next value that will be received.
    next: usize,
    _marker: PhantomData<C>,
}

impl<S, C> OperatingState<S, C>
where
    S: Stream<Item = C>,
    C: AsRef<[u8]>,
{
    /// Determine whether `i` is the next record that we expect to receive.
    fn is_next(&self, i: usize) -> bool {
        i == self.next
    }

    /// Track a waker from a future that was invoked before data was ready.
    ///
    /// Note that this only tracks the last waker for each index, which appears
    /// to violate the contract for `Future` implementations.  That shouldn't a
    /// problem in practice because we expect [`recv`] to be called only once,
    /// which produces just one `Future`.  Informing the last context to [`poll`]
    /// that `Future` should at least ensure that things progress, even if we
    /// don't guarantee that all contexts are awoken.
    ///
    /// # Panics
    ///
    /// If `i` is for an message that has already been read.
    ///
    /// [`recv`]: UnorderedReceiver::recv
    /// [`poll`]: Future::poll
    fn add_waker(&mut self, i: usize, waker: Waker) {
        // We don't save a waker at `self.next`, so `>` and not `>=`.
        if i > self.next + self.wakers.len() {
            self.overflow_wakers.push(waker);
        } else {
            assert!(
                i > self.next,
                "Awaiting a read that has already been fulfilled"
            );
            let index = i % self.wakers.len();
            self.wakers[index] = Some(waker);
        }
    }

    /// Wake the waker from the next future, if the next receiver has been polled.
    fn wake_next(&mut self) {
        self.next += 1;
        let index = self.next % self.wakers.len();
        if let Some(w) = self.wakers[index].take() {
            w.wake();
        }
        // See the documentation for `overflow_wakers`.
        if self.next % (self.wakers.len() / 2) == 0 {
            for w in self.overflow_wakers.drain(..) {
                w.wake();
            }
        }
    }

    /// Poll for the next record.  This should only be invoked when
    /// the future for the next message is polled.
    fn poll_next<M: Message>(&mut self, cx: &mut Context<'_>) -> Poll<Result<M, Error>> {
        if let Some(m) = self.spare.read() {
            self.wake_next();
            return Poll::Ready(Ok(m));
        }

        loop {
            match self.stream.as_mut().poll_next(cx) {
                Poll::Pending => {
                    return Poll::Pending;
                }
                Poll::Ready(Some(b)) => {
                    if let Some(m) = self.spare.extend(b.as_ref()) {
                        self.wake_next();
                        return Poll::Ready(Ok(m));
                    }
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(Error::EndOfStream {
                        record_id: RecordId::from(self.next),
                    }));
                }
            }
        }
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

#[allow(dead_code)]
impl<S, C> UnorderedReceiver<S, C>
where
    S: Stream<Item = C>,
    C: AsRef<[u8]>,
{
    /// Wrap a stream for unordered reading.
    ///
    /// The capacity here determines how far ahead a read can be.  In most cases,
    /// this should be the same as the value given to [`ordering_mpsc`].
    ///
    /// [`ordering_mpsc`]: crate::helpers::buffers::ordering_mpsc::ordering_mpsc
    pub fn new(stream: Pin<Box<S>>, capacity: NonZeroUsize) -> Self {
        let mut wakers = Vec::with_capacity(capacity.get());
        wakers.resize(capacity.get(), None);
        Self {
            inner: Arc::new(Mutex::new(OperatingState {
                stream,
                wakers,
                overflow_wakers: Vec::new(),
                next: 0,
                spare: Spare::default(),
                _marker: PhantomData,
            })),
        }
    }

    /// Ask to receive from the stream at index `i`.
    ///
    /// This method can be called multiple times with the same value for `i`,
    /// but only one of the futures can be polled until it succeeds.
    /// Once one future is resolved, the other will crash.
    pub fn recv<M: Message>(&self, i: usize) -> Receiver<S, C, M> {
        Receiver {
            i,
            receiver: Arc::clone(&self.inner),
            _marker: PhantomData,
        }
    }
}

impl<S, C> Clone for UnorderedReceiver<S, C>
where
    S: Stream<Item = C>,
    C: AsRef<[u8]>,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        bits::Serializable,
        ff::{Fp31, Fp32BitPrime},
        helpers::buffers::unordered_receiver::UnorderedReceiver,
    };
    use futures::{
        future::{try_join, try_join_all},
        stream::iter,
        Future, FutureExt, Stream,
    };
    use generic_array::GenericArray;
    use rand::Rng;
    #[cfg(feature = "shuttle")]
    use shuttle::future::spawn;
    use std::num::NonZeroUsize;
    #[cfg(not(feature = "shuttle"))]
    use tokio::spawn;
    use typenum::Unsigned;

    fn receiver<I, T>(it: I) -> UnorderedReceiver<impl Stream<Item = T>, T>
    where
        I: IntoIterator<Item = T> + 'static,
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
                            assert_eq!(f, Fp31::from(u128::from(v)));
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
                    let f: Fp31 = recv.recv(0).await.unwrap();
                    assert_eq!(f, Fp31::from(18_u128));
                }
            }),
            spawn({
                let recv = recv.clone();
                async move {
                    let f: Fp32BitPrime = recv.recv(1).await.unwrap();
                    assert_eq!(f, Fp32BitPrime::from(0x0100_020c_u128));
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
    fn synchronous() {
        const DATA: &[u8] = &[18, 12];
        let recv = receiver(&[DATA]);
        assert!(recv.recv::<Fp31>(1).now_or_never().is_none());
        for (i, &v) in DATA.iter().enumerate() {
            let f: Fp31 = recv.recv(i).now_or_never().unwrap().unwrap();
            assert_eq!(f, Fp31::from(u128::from(v)));
        }
    }

    /// Register more reads than the receiver has the capacity to track.
    /// Start by registering those that are furthest into the future, so
    /// that we can ensure that we exercise the overflow tracking mechanism.
    #[test]
    fn too_many_reads() {
        const DATA: &[u8] = &[8, 9, 10, 11, 13, 17];
        run(|| {
            let recv = receiver(vec![DATA.to_vec()]);
            async move {
                try_join_all(DATA.iter().enumerate().rev().map(|(i, &v)| {
                    spawn({
                        let recv = recv.clone();
                        async move {
                            let f: Fp31 = recv.recv(i).await.unwrap();
                            assert_eq!(f, Fp31::from(u128::from(v)));
                        }
                    })
                }))
                .await
                .unwrap();
            }
        });
    }
}
