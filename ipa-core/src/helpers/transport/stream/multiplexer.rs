use std::{
    collections::VecDeque,
    io,
    io::Error,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll, Waker},
};

use bytes::Bytes;
use futures::Stream;

use crate::{
    helpers::{BytesStream, LengthDelimitedStream},
    sync::{atomic::AtomicUsize, Arc, Mutex},
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
        // Short circuit to avoid contention on poller when outer stream is closed.
        if let Poll::Ready(value) = self.poller.closed_for(self.index) {
            return Poll::Ready(value);
        }

        if self.poller.next.load(Ordering::Acquire) == self.index {
            self.poller.poll_next(self.index, cx)
        } else {
            // it is not our turn, register waker and wait.
            self.poller.register_waker(self.index, cx.waker().clone());
            Poll::Pending
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
    pub fn poll_next(
        self: &Arc<Self>,
        shard: usize,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, MultiplexError>>> {
        // To avoid contention, this function must be called after the check that `shard` == `next`
        debug_assert_eq!(shard, self.next.load(Ordering::Acquire));

        let mut inner = self.state.lock().unwrap();
        let next = (shard + 1) % self.consumers.len();
        if !inner.buf.is_empty() {
            let buf = inner.buf.pop_front();
            self.wake(next);

            return Poll::Ready(buf.map(Ok));
        }

        match unsafe { Pin::new_unchecked(&mut inner.stream) }
            .as_mut()
            .poll_next(cx)
        {
            // When data is ready, push it to the buffer and wake the next shard.
            Poll::Ready(Some(Ok(data))) => {
                inner.buf.extend(data);
                self.wake(next);

                Poll::Ready(inner.buf.pop_front().map(Ok))
            }
            // Stream is either closed or generated an error. Closing this poller and notifying
            // consumers.
            Poll::Ready(v) => {
                let r = self.close_with(shard, v);
                self.wake(next);

                r
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn closed_for(
        self: &Arc<Self>,
        consumer_index: usize,
    ) -> Poll<Option<Result<Bytes, MultiplexError>>> {
        let mut shard = self.consumers[consumer_index].lock().unwrap();

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

    fn wake(self: &Arc<Self>, consumer_index: usize) {
        self.next.store(consumer_index, Ordering::Release);

        let mut shard = self.consumers[consumer_index].lock().unwrap();
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

    use std::{fmt::Debug, iter::Map};

    use bytes::{Bytes, BytesMut};
    use futures::{stream, Stream};
    use futures_util::StreamExt;
    use generic_array::GenericArray;
    use proptest::{collection::vec, proptest};

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
