use futures::{task::Waker, Future, Stream};
use pin_project::pin_project;
use std::{
    cmp::Ordering,
    collections::BinaryHeap,
    marker::PhantomData,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use crate::{
    helpers::{messaging::Message, Error},
    protocol::RecordId,
};

/// A holder for the `Waker` of the `i`th item.
struct Waiting {
    i: usize,
    waker: Waker,
}

impl Waiting {
    fn wake(self) {
        self.waker.wake();
    }
}

impl PartialEq for Waiting {
    fn eq(&self, other: &Self) -> bool {
        self.i == other.i
    }
}
impl Eq for Waiting {}

impl PartialOrd for Waiting {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Waiting {
    fn cmp(&self, other: &Self) -> Ordering {
        other.i.cmp(&self.i)
    }
}

/// The state for the future we return for each receive attempt.
/// This is used to track the collection of a waker so that we can
/// notify correctly.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Uninit,
    Waiting,
    Active,
}

/// A future for the receipt of item `i` from the `UnorderedReceiver`.
#[pin_project]
pub struct Receiver<S, C, CA, CE, M>
where
    S: Stream<Item = C>,
    C: TryInto<CA, Error = CE>,
    CA: AsRef<[u8]>,
    Error: From<CE>,
    M: Message,
{
    #[pin]
    i: usize,
    #[pin]
    receiver: Arc<Mutex<Inner<S, C, CA, CE>>>,
    #[pin]
    state: State,
    _marker: PhantomData<M>,
}

impl<S, C, CA, CE, M> Future for Receiver<S, C, CA, CE, M>
where
    S: Stream<Item = C>,
    C: TryInto<CA, Error = CE>,
    CA: AsRef<[u8]>,
    Error: From<CE>,
    M: Message,
{
    type Output = Result<M, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.as_mut().project();
        let mut recv = this.receiver.lock().unwrap();
        if *this.state == State::Uninit {
            *this.state = if recv.is_next(*this.i) {
                State::Active
            } else {
                recv.add_waker(*this.i, cx.waker().clone());
                State::Waiting
            };
        } else if *this.state == State::Waiting && recv.is_next(*this.i) {
            *this.state = State::Active;
        }
        if *this.state == State::Active {
            recv.poll_active(cx)
        } else {
            Poll::Pending
        }
    }
}

#[derive(Default)]
struct Spare {
    buf: Vec<u8>,
    offset: usize,
}

impl Spare {
    /// Read a value from the buffer.  Returns `None` if there isn't enough data.
    fn read<M: Message>(&mut self) -> Option<M> {
        let end = self.offset + M::SIZE_IN_BYTES;
        if end <= self.buf.len() {
            let m = M::deserialize(&self.buf[self.offset..end]).unwrap();
            self.offset = end;
            Some(m)
        } else {
            None
        }
    }

    /// Extend the buffer with new data.  This might return a value if there is enough data.
    fn extend<M: Message>(&mut self, v: &[u8]) -> Option<M> {
        let remainder = self.buf.len() - self.offset;
        if remainder + v.len() < M::SIZE_IN_BYTES {
            // Not enough data: save it.
            // If we're working from the tail of a longer buffer, just keep the tail.
            self.buf = self.buf.split_off(self.offset);
            self.buf.extend_from_slice(v);
            self.offset = 0;
            return None;
        }

        let (m, taken) = if remainder > 0 {
            // Need to join a piece of the remainder and the new stuff.  On the stack then.
            let take = M::SIZE_IN_BYTES - remainder;
            let mut tmp = [0; 32];
            assert!(M::SIZE_IN_BYTES < tmp.len());
            tmp[..remainder].copy_from_slice(&self.buf[self.offset..]);
            tmp[remainder..M::SIZE_IN_BYTES].copy_from_slice(&v[..take]);
            (M::deserialize(&tmp[..M::SIZE_IN_BYTES]).unwrap(), take)
        } else {
            (
                M::deserialize(&v[..M::SIZE_IN_BYTES]).unwrap(),
                M::SIZE_IN_BYTES,
            )
        };
        self.buf = v[taken..].to_vec();
        self.offset = 0;
        Some(m)
    }
}

pub struct Inner<S, C, CA, CE>
where
    S: Stream<Item = C>,
    C: TryInto<CA, Error = CE>,
    CA: AsRef<[u8]>,
    Error: From<CE>,
{
    /// The stream we're reading from.
    stream: Pin<Box<S>>,
    /// This tracks `Waker` instances from calls to `recv()` with indices that
    /// aren't ready at the time of the call.  If the future is invoked prior
    /// to the value being ready, the `Waker` is saved here.
    waiting: BinaryHeap<Waiting>,
    /// Left over data from a previous `recv()` call.  The underlying stream
    /// can provide chunks of data larger than a single message.  We save the
    /// spare data here.
    spare: Spare,
    /// The next index that will be read from the stream (or the spare).
    next: usize,
    _marker: PhantomData<(C, CA, CE)>,
}

impl<S, C, CA, CE> Inner<S, C, CA, CE>
where
    S: Stream<Item = C>,
    C: TryInto<CA, Error = CE>,
    CA: AsRef<[u8]>,
    Error: From<CE>,
{
    /// Determine whether `i` is the next record that we expect to receive.
    fn is_next(&self, i: usize) -> bool {
        i == self.next
    }

    /// Track a waker from a future that was invoked before data was ready.
    fn add_waker(&mut self, i: usize, waker: Waker) {
        assert!(i > self.next, "Second attempt to read index {i}");
        self.waiting.push(Waiting { i, waker });
    }

    /// Wake the waker from the next future, if that is the next one.
    fn wake_next(&mut self) {
        self.next += 1;
        if let Some(n) = self.waiting.peek() {
            if n.i == self.next {
                self.waiting.pop().unwrap().wake();
            }
        }
    }

    /// Poll for the next record.  This should only be invoked when the future for the next
    /// message is polled.
    fn poll_active<M: Message>(&mut self, cx: &mut Context<'_>) -> Poll<Result<M, Error>> {
        if let Some(m) = self.spare.read() {
            self.wake_next();
            return Poll::Ready(Ok(m));
        }

        match self.stream.as_mut().poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(b)) => {
                let extra = b.try_into()?;
                if let Some(m) = self.spare.extend(extra.as_ref()) {
                    self.wake_next();
                    Poll::Ready(Ok(m))
                } else {
                    Poll::Pending
                }
            }
            Poll::Ready(None) => Poll::Ready(Err(Error::EndOfStream {
                record_id: RecordId::from(self.next),
            })),
        }
    }
}

/// Take an ordered stream of bytes and make messages from that stream available in any order.
pub struct UnorderedReceiver<S, C, CA, CE>
where
    S: Stream<Item = C>,
    C: TryInto<CA, Error = CE>,
    CA: AsRef<[u8]>,
    Error: From<CE>,
{
    inner: Arc<Mutex<Inner<S, C, CA, CE>>>,
}

#[allow(dead_code)]
impl<S, C, CA, CE> UnorderedReceiver<S, C, CA, CE>
where
    S: Stream<Item = C>,
    C: TryInto<CA, Error = CE>,
    CA: AsRef<[u8]>,
    Error: From<CE>,
{
    /// Wrap a stream.
    pub fn new(stream: Pin<Box<S>>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                stream,
                waiting: BinaryHeap::new(),
                spare: Spare::default(),
                next: 0,
                _marker: PhantomData,
            })),
        }
    }

    /// Ask to receive from the stream at index `i`.
    pub fn recv<M: Message>(&self, i: usize) -> Receiver<S, C, CA, CE, M> {
        Receiver {
            i,
            receiver: Arc::clone(&self.inner),
            state: State::Uninit,
            _marker: PhantomData,
        }
    }
}

impl<S, C, CA, CE> Clone for UnorderedReceiver<S, C, CA, CE>
where
    S: Stream<Item = C>,
    C: TryInto<CA, Error = CE>,
    CA: AsRef<[u8]>,
    Error: From<CE>,
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
        ff::{Fp31, Fp32BitPrime},
        helpers::{buffers::unordered_receiver::UnorderedReceiver, Error},
    };
    use futures::{
        future::{try_join, try_join_all},
        stream::unfold,
        Future, FutureExt, Stream,
    };
    #[cfg(feature = "shuttle")]
    use shuttle::future::spawn;
    #[cfg(not(feature = "shuttle"))]
    use tokio::spawn;

    struct StreamItem<'a>(&'a [u8]);
    impl<'a> TryInto<&'a [u8]> for StreamItem<'a> {
        type Error = Error;
        fn try_into(self) -> Result<&'a [u8], Self::Error> {
            Ok(self.0)
        }
    }

    fn receiver(
        data: &[u8],
    ) -> UnorderedReceiver<impl Stream<Item = StreamItem<'_>>, StreamItem<'_>, &[u8], Error> {
        let stream = unfold(Some(data), |data| async move {
            data.map(|d| (StreamItem(d), None))
        });
        UnorderedReceiver::<_, _, &[u8], _>::new(Box::pin(stream))
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

        run(|| async {
            let recv = receiver(DATA);
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
        });
    }

    #[test]
    fn different_types() {
        const DATA: &[u8] = &[18, 12, 2, 0, 1];

        run(|| async {
            let recv = receiver(DATA);
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
        });
    }

    #[test]
    fn synchronous() {
        const DATA: &[u8] = &[18, 12];
        let recv = receiver(DATA);
        assert!(recv.recv::<Fp31>(1).now_or_never().is_none());
    }
}
