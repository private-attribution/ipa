use std::{
    collections::VecDeque,
    io,
    io::Error,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use bytes::Bytes;
use futures::Stream;

use crate::{
    helpers::{BytesStream, LengthDelimitedStream},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

/// Errors received from the input stream must be replicated to reach every consumer, `Arc` allows
/// us to do that in async world.
type MultiplexError = Arc<io::Error>;

pub trait ConsumerStream: Stream<Item = Result<Bytes, MultiplexError>> {}
impl<S: Stream<Item = Result<Bytes, MultiplexError>>> ConsumerStream for S {}

/// This function takes a stream of bytes that represent a stream of RLE-encoded records and multiplexes
/// each record into output streams based on deterministic Round-robin strategy. For example,
/// running this function on a stream with 5 records and requesting 5 output streams, each stream will
/// have produce only one record, with stream 1 getting record 1, stream 2 getting record 2, etc.
///
/// It is guaranteed that the resulting vector has the size of `shards`.
///
/// ## Performance
/// This function avoids heavy contention on the `input` by imposing the strict order in which it
/// is polled by the resulting streams. Thus, all stream handles must be polled to make progress
/// and drain the `input`.
///
/// ## Errors
/// If the input stream produces an error, it gets sent to all shards and this stream stops producing
/// any more data.
pub fn multiplex<S: BytesStream>(input: S, shards: usize) -> Vec<impl ConsumerStream> {
    let poller = Arc::new(Poller {
        consumers: (0..shards)
            .map(|_| ConsumerState::default())
            .map(Mutex::new)
            .collect(),
        state: Mutex::new(State {
            stream: LengthDelimitedStream::new(input),
            buf: VecDeque::default(),
        }),
        next: AtomicUsize::default(),
        closed: AtomicBool::default(),
    });

    (0..shards)
        .map(|shard| PollingEnd {
            index: shard,
            poller: Arc::clone(&poller),
        })
        .collect()
}

/// The state for each consumer stream that polls `Poller`.
#[derive(Default)]
struct ConsumerState {
    waker: Option<Waker>,
    /// Error set by the `Poller` if the outer stream failed.
    last_error: Option<MultiplexError>,
}

struct PollingEnd<S: BytesStream> {
    index: usize,
    poller: Arc<Poller<S>>,
}

impl<S: BytesStream> Stream for PollingEnd<S> {
    type Item = Result<Bytes, MultiplexError>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Check if it is our turn to get the data, if not - register our waker and return pending
        if self.poller.is_next(self.index) {
            self.poller.take_next(self.index, cx)
        } else {
            self.poller.register_waker(self.index, cx.waker().clone());
            // This is the part where we have to check the next index again because of a potential
            // race between the writer (this thread that tries to save its waker) and the reader (thread that
            // wakes up the next task). If we got unlucky,  another thread has already tried to wake
            // our waker but couldn't find it because it happened before `register_waker` call.
            // If that happens, poller's next pointer will be updated at this point, and can tell us
            // if we need to try again.
            if self.poller.is_next(self.index) {
                self.poller.take_next(self.index, cx)
            } else {
                Poll::Pending
            }
        }
    }
}

/// Allows N consumers to poll `S` in strict order. Closes all of them if `S` generates an error.
struct Poller<S: BytesStream> {
    /// Set of downstreams that request data from this poller.
    consumers: Vec<Mutex<ConsumerState>>,
    state: Mutex<State<S>>,
    /// Next stream that will be receiving data. Is always within the range `0...shards.len()`
    next: AtomicUsize,
    /// Set to true when the outer stream is closed due to an error or if fully drained.
    closed: AtomicBool,
}

struct State<S: BytesStream> {
    stream: LengthDelimitedStream<Bytes, S>,
    buf: VecDeque<Bytes>,
}

impl<S: BytesStream> Poller<S> {
    pub fn is_next(self: &Arc<Self>, cur: usize) -> bool {
        self.next.load(Ordering::Acquire) == cur
    }

    pub fn take_next(
        self: &Arc<Self>,
        cur: usize,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, MultiplexError>>> {
        // To avoid contention, this function must be called after the check that `shard` == `next`
        debug_assert_eq!(cur, self.next.load(Ordering::Acquire));

        let r = if let Poll::Ready(value) = self.is_closed_or_failed(cur) {
            // Short circuit to avoid contention on poller when outer stream is closed.
            Poll::Ready(value)
        } else {
            // expensive path, requires a lock on shared the state.
            // We check if there is data already in the buffer, and if not, we poll the outer stream.
            let mut inner = self.state.lock().unwrap();
            if inner.buf.is_empty() {
                // SAFETY: stream is never moved out of this struct. Unsafe code seems to be the only
                // ergonomic way to get pinned reference from inside a mutex.
                match unsafe { Pin::new_unchecked(&mut inner.stream) }
                    .as_mut()
                    .poll_next(cx)
                {
                    // When data is ready, push it to the buffer and wake the next shard.
                    Poll::Ready(Some(Ok(data))) => {
                        inner.buf.extend(data);

                        Poll::Ready(inner.buf.pop_front().map(Ok))
                    }
                    // Stream is either closed or generated an error. Closing this poller and notifying
                    // consumers.
                    Poll::Ready(v) => self.close_with(cur, v),
                    Poll::Pending => Poll::Pending,
                }
            } else {
                let buf = inner.buf.pop_front();

                Poll::Ready(buf.map(Ok))
            }
        };

        if r.is_ready() {
            // if there is something to return, we must notify the next consumer stream that
            // it is their turn to poll for data.
            self.wake_next(cur);
        }

        r
    }

    fn is_closed_or_failed(
        self: &Arc<Self>,
        cur: usize,
    ) -> Poll<Option<Result<Bytes, MultiplexError>>> {
        let mut shard = self.consumers[cur].lock().unwrap();

        if let Some(err) = shard.last_error.take() {
            Poll::Ready(Some(Err(err)))
        } else if self.closed.load(Ordering::Acquire) {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }

    fn register_waker(self: &Arc<Self>, consumer_index: usize, waker: Waker) {
        let mut shard = self.consumers[consumer_index].lock().unwrap();
        if let Some(ref w) = shard.waker {
            assert!(w.will_wake(&waker));
        }

        shard.waker.replace(waker);
    }

    fn wake_next(self: &Arc<Self>, cur: usize) {
        let next = (cur + 1) % self.consumers.len();
        self.next.store(next, Ordering::Release);

        let mut shard = self.consumers[next].lock().unwrap();
        if let Some(waker) = shard.waker.take() {
            waker.wake();
        }
    }

    fn close_with(
        self: &Arc<Self>,
        exclude: usize,
        close_result: Option<Result<Vec<Bytes>, Error>>,
    ) -> Poll<Option<Result<Bytes, MultiplexError>>> {
        self.closed.store(true, Ordering::Release);

        // Replicate the error across all consumers
        if let Some(Err(e)) = close_result {
            let shared_err = Arc::new(e);
            for (i, consumer) in self.consumers.iter().enumerate() {
                if i != exclude {
                    let mut shard = consumer.lock().unwrap();
                    shard.last_error.replace(Arc::clone(&shared_err));
                }
            }

            Poll::Ready(Some(Err(shared_err)))
        } else {
            Poll::Ready(None)
        }
    }
}

#[cfg(all(test, any(unit_test, feature = "shuttle")))]
mod tests {

    use std::{fmt::Debug, iter::Map, str::FromStr};

    use bytes::{Bytes, BytesMut};
    use futures::{
        future::poll_immediate,
        stream,
        stream::{FusedStream, FuturesUnordered},
        Stream, StreamExt, TryStreamExt,
    };
    use generic_array::GenericArray;
    use proptest::{collection::vec, proptest};
    use rand::{thread_rng, Rng};

    use crate::{
        error::BoxError,
        ff::Serializable,
        helpers::transport::stream::{
            input::Length,
            multiplexer::{multiplex, MultiplexError},
        },
        test_executor::run,
    };

    trait RleEncoder {
        type Output;
        fn encode_rl(self) -> Self::Output;
    }

    impl RleEncoder for String {
        type Output = Bytes;
        fn encode_rl(self) -> Bytes {
            let bytes = self.into_bytes();
            let len = Length::try_from(bytes.len()).unwrap();
            let mut encoded_bytes = Vec::with_capacity(bytes.len() + 2);
            encoded_bytes.extend(&[0; 2]);
            len.serialize(GenericArray::from_mut_slice(&mut encoded_bytes[..2]));
            encoded_bytes.extend(bytes);

            Bytes::from(encoded_bytes)
        }
    }

    impl RleEncoder for &str {
        type Output = Bytes;

        fn encode_rl(self) -> Self::Output {
            self.to_owned().encode_rl()
        }
    }

    impl<R: RleEncoder> RleEncoder for Vec<R> {
        type Output =
            stream::Iter<Map<std::vec::IntoIter<R>, fn(R) -> Result<R::Output, BoxError>>>;

        fn encode_rl(self) -> Self::Output {
            #[allow(clippy::unnecessary_wraps)] // Trait bounds require using `Result` type.
            fn mapper<R: RleEncoder>(input: R) -> Result<R::Output, BoxError> {
                Ok(input.encode_rl())
            }

            stream::iter(
                self.into_iter()
                    .map(mapper as fn(R) -> Result<R::Output, BoxError>),
            )
        }
    }
    impl<R: RleEncoder, const N: usize> RleEncoder for [R; N] {
        type Output = <Vec<R> as RleEncoder>::Output;
        fn encode_rl(self) -> Self::Output {
            self.into_iter().collect::<Vec<_>>().encode_rl()
        }
    }
    async fn collect_all<
        S: Stream<Item = Result<Bytes, MultiplexError>> + Unpin + 'static,
        T,
        F: Fn(S::Item) -> T,
    >(
        input: Vec<S>,
        combiner: F,
    ) -> Vec<Vec<T>> {
        let mut result = input.iter().map(|_| Vec::new()).collect::<Vec<_>>();
        let mut streams = stream::select_all(
            input
                .into_iter()
                .enumerate()
                .map(|(stream_id, stream)| stream.map(move |r| (stream_id, r))),
        );
        while let Some((index, item)) = streams.next().await {
            result[index].push(combiner(item));
        }

        result
    }

    fn string_or_panic<E: Debug>(value: Result<Bytes, E>) -> String {
        String::from_utf8(value.unwrap().to_vec()).unwrap()
    }

    #[test]
    fn spsc() {
        run(|| async move {
            let input = ["hello", "world"].encode_rl();
            assert_eq!(
                vec![vec!["hello", "world"]],
                collect_all(multiplex(input, 1), string_or_panic).await
            );
        });
    }

    #[test]
    fn even_split() {
        run(|| async move {
            let input = ["hello", "world", "here"].encode_rl();
            assert_eq!(
                vec![vec!["hello"], vec!["world"], vec!["here"]],
                collect_all(multiplex(input, 3), string_or_panic).await
            );
        });
    }

    #[test]
    fn uneven_split() {
        run(|| async move {
            let input = ["first", "second", "eleventh"].encode_rl();
            assert_eq!(
                vec![vec!["first"], vec!["second"], vec!["eleventh"], vec![]],
                collect_all(multiplex(input, 4), string_or_panic).await
            );

            let input = (0..=10)
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .encode_rl();
            assert_eq!(
                vec![
                    vec!["0", "3", "6", "9"],
                    vec!["1", "4", "7", "10"],
                    vec!["2", "5", "8"]
                ],
                collect_all(multiplex(input, 3), string_or_panic).await
            );
        });
    }

    #[test]
    fn empty() {
        run(|| async move {
            assert_eq!(
                collect_all(multiplex(stream::empty(), 2), string_or_panic).await,
                vec![Vec::<&str>::new(); 2]
            );
        });
    }

    #[test]
    fn error() {
        run(|| async move {
            let input = stream::iter(vec![
                Ok::<_, BoxError>("hello".encode_rl()),
                Err("should stop here".into()),
                Ok("world".encode_rl()),
            ]);
            let [s1, s2, s3] = collect_all(multiplex(input, 3), |item| match item {
                Ok(bytes) => String::from_utf8(bytes.to_vec()).unwrap(),
                Err(e) => format!("{e}"),
            })
            .await
            .try_into()
            .unwrap();
            assert_eq!(vec!["hello", "should stop here"], s1);
            assert_eq!(vec!["should stop here"], s2);
            assert_eq!(vec!["should stop here"], s3);
        });
    }

    #[test]
    fn chunks_variable_size() {
        run(|| async move {
            let mut c1 = BytesMut::from("hello".encode_rl().as_ref());
            c1.extend("world".encode_rl());
            let input = stream::iter(vec![Ok::<_, BoxError>(c1.freeze()), Ok("!".encode_rl())]);
            assert_eq!(
                vec![vec!["hello"], vec!["world"], vec!["!"]],
                collect_all(multiplex(input, 3), string_or_panic).await
            );
        });
    }

    #[test]
    fn random_order() {
        run(|| async move {
            let numbers = (0..100).map(|i| i.to_string()).collect::<Vec<_>>();
            let input = numbers.clone().encode_rl();
            let mut streams = multiplex(input, 20)
                .into_iter()
                .map(StreamExt::fuse)
                .collect::<Vec<_>>();
            let mut results = Vec::new();

            // This loop picks a random stream and polls it. If stream makes progress, it gets an
            // item from it and moves on. If stream returns Poll::Pending, it simply abandons its
            // future and moves to another iteration. Loop terminates when all streams are completed.
            loop {
                if streams.is_empty() {
                    break;
                }

                let idx = thread_rng().gen_range(0..streams.len());
                let stream = streams.get_mut(idx).unwrap();

                match poll_immediate(stream.next()).await {
                    Some(Some(v)) => results.push(String::from_utf8(v.unwrap().to_vec()).unwrap()),
                    Some(None) => {
                        let s = streams.remove(idx);
                        assert!(s.is_terminated());
                    }
                    None => {}
                }
            }

            results.sort_by_key(|s| u16::from_str(s).unwrap());
            assert_eq!(numbers, results);
        });
    }

    #[test]
    fn multithreading() {
        #[cfg(feature = "shuttle")]
        use shuttle::future as tokio;

        run(|| async move {
            let numbers = (0..10).map(|i| i.to_string()).collect::<Vec<_>>();
            let input = numbers.clone().encode_rl();
            let streams = multiplex(input, 3)
                .into_iter()
                .map(StreamExt::fuse)
                .collect::<Vec<_>>();

            let results: Vec<Vec<_>> = streams
                .into_iter()
                .map(|s| tokio::spawn(async move { s.try_collect().await.unwrap() }))
                .collect::<FuturesUnordered<_>>()
                .try_collect()
                .await
                .unwrap();

            // convert to strings
            let mut results = results
                .into_iter()
                .flatten()
                .map(|bytes| String::from_utf8(bytes.to_vec()).unwrap())
                .collect::<Vec<_>>();

            results.sort_by_key(|s| u16::from_str(s).unwrap());
            assert_eq!(numbers, results);
        });
    }

    async fn no_phantoms(input: Vec<String>, shards: usize) {
        let output = collect_all(
            multiplex(input.clone().encode_rl(), shards),
            string_or_panic,
        )
        .await;

        assert_eq!(output.len(), shards);
        output.into_iter().enumerate().for_each(|(i, shard)| {
            assert!(input.iter().skip(i).step_by(shards).eq(shard.iter()));
        });
    }

    proptest! {
        #[test]
        fn prop_no_phantoms(input in vec("[A-Za-z0-9]{0,3}", 0..80), shards in 0_usize..19) {
            run(move || {
                let input = input.clone();
                async move { no_phantoms(input, shards).await; }
            });
        }
    }
}
