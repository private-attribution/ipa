use std::{
    io::BufRead,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use bytes::Bytes;
use futures::Stream;

use crate::{
    error::BoxError,
    helpers::BytesStream,
    sync::{Arc, Mutex},
};

/// Trait for submitting inputs as streams, rather than reading everything
/// in memory. Should provide better performance for very large inputs.
trait StreamingSubmission {
    /// Spits itself into `count` instances of [`BytesStream`].
    fn into_byte_streams(self, count: usize) -> Vec<impl BytesStream>;
}

/// Round-Robin strategy to read off the provided buffer
/// and distribute them. Inputs is expected to be hex-encoded
/// and delimited by newlines. The output streams will have
/// run-length encoding, meaning that each element will have
/// a 2 byte length prefix added to it.
struct RoundRobinSubmission<R>(R);

impl<R: BufRead> RoundRobinSubmission<R> {
    pub fn new(read_from: R) -> Self {
        Self(read_from)
    }
}

/// One individual stream that reads from the shared input for [`RoundRobinSubmission`]
struct RoundRobinStream<R> {
    /// Points to the shared state.
    state: Arc<Mutex<State<R>>>,
    /// Unique identifier of this stream
    idx: usize,
}

impl<R: BufRead> Stream for RoundRobinStream<R> {
    type Item = Result<Bytes, BoxError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut state = self.state.lock().unwrap();
        // it can be made more efficient by using atomics to check index.
        // but probably it does not matter for this code as it is not on the hot path
        if state.idx == self.idx {
            let poll = state.read_next();
            if poll.is_ready() {
                let new_idx = (state.idx + 1) % state.wakers.len();
                state.idx = new_idx;
                if let Some(waker) = state.wakers[new_idx].take() {
                    waker.wake();
                }
            }

            poll
        } else {
            state.wakers[self.idx] = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl<R: BufRead + Send> StreamingSubmission for RoundRobinSubmission<R> {
    fn into_byte_streams(self, count: usize) -> Vec<impl BytesStream> {
        let state = Arc::new(Mutex::new(State {
            read_from: self.0,
            wakers: vec![None; count],
            idx: 0,
            buf: Vec::new(),
        }));

        (0..count)
            .map(|idx| RoundRobinStream {
                state: Arc::clone(&state),
                idx,
            })
            .collect()
    }
}

/// Internal state for [`RoundRobinSubmission`] implementation
struct State<R> {
    /// The input, we're reading from.
    read_from: R,
    /// List of wakers for streams that wait for their turn
    wakers: Vec<Option<Waker>>,
    /// Pointer to the stream that is next to poll this buffer
    idx: usize,
    /// Reusable buffer to keep the bytes read from the input.
    /// The idea here is to re-use the same allocation across
    /// multiple reads. As we are reading line-by-line, it is likely
    /// that those reads have the same size.
    buf: Vec<u8>,
}

impl<R: BufRead> State<R> {
    /// Attempts to read the next block from the input and convert it into
    /// format accepted by [`BytesStream`]. As input is expected to be hex-encoded,
    /// performs the decoding operation too.
    fn read_next(&mut self) -> Poll<Option<Result<Bytes, BoxError>>> {
        const NEWLINE: u8 = b'\n';
        // max encodable size of a single item must fit into 16 bits integer.
        const MAX_SIZE: usize = 1 << 16;
        let read = self.read_from.read_until(NEWLINE, &mut self.buf);
        match read {
            Ok(0) => Poll::Ready(None),
            Ok(_) => {
                // remove the trailing newline
                if self.buf.last() == Some(&NEWLINE) {
                    self.buf.pop();
                }
                // input comes in encoded, we need to decode it first
                let bytes = hex::decode(&self.buf)
                    .map_err(Into::into)
                    .and_then(|v| {
                        if v.len() < MAX_SIZE {
                            Ok(v)
                        } else {
                            Err(format!(
                                "Element size {} is too big to be encoded using RLE encoding",
                                v.len()
                            )
                            .into())
                        }
                    })
                    .map(|v| {
                        let mut rle_v = vec![0_u8; v.len() + size_of::<u16>()];
                        // u16 fit is enforced one line above
                        rle_v[..2]
                            .copy_from_slice(&(u16::try_from(v.len()).unwrap().to_le_bytes()));
                        rle_v[2..].copy_from_slice(&v);

                        Bytes::from(rle_v)
                    });
                self.buf.clear();
                Poll::Ready(Some(bytes))
            }
            Err(e) => Poll::Ready(Some(Err(e.into()))),
        }
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::{
        fs::File,
        io::{BufReader, Write},
        iter,
    };

    use futures_util::{stream::FuturesOrdered, TryStreamExt};
    use proptest::proptest;
    use tempfile::TempDir;

    use crate::{
        cli::playbook::streaming::{RoundRobinSubmission, StreamingSubmission},
        helpers::BytesStream,
        test_executor::run,
    };

    async fn drain_all<S: BytesStream>(streams: Vec<S>) -> Vec<String> {
        let mut futs = FuturesOrdered::default();
        for s in streams {
            futs.push_back(s.try_fold(String::new(), |mut acc, chunk| async move {
                // remove RLE decoding
                let len = usize::from(u16::from_le_bytes(chunk[..2].try_into().unwrap()));
                assert_eq!(len, chunk.len() - 2);
                acc.push_str(&String::from_utf8_lossy(&chunk[2..]));
                Ok(acc)
            }));
        }

        futs.try_collect::<Vec<_>>().await.unwrap()
    }

    fn encoded<I: IntoIterator<Item: AsRef<[u8]>>>(input: I) -> Vec<String> {
        input.into_iter().map(|s| hex::encode(s.as_ref())).collect()
    }

    #[test]
    fn basic() {
        run(|| verify_one(vec!["foo", "bar", "baz", "qux", "quux"], 3));
    }

    #[test]
    #[should_panic(expected = "InvalidHexCharacter")]
    fn non_hex() {
        run(|| async {
            drain_all(
                RoundRobinSubmission::new("zzzz\nxxx\nyyy\nxxx\n".as_bytes()).into_byte_streams(3),
            )
            .await;
        });
    }

    #[test]
    #[should_panic(expected = "OddLength")]
    fn bad_hex() {
        run(|| async {
            drain_all(
                RoundRobinSubmission::new("fff\n0xdeadbeef\n".as_bytes()).into_byte_streams(3),
            )
            .await;
        });
    }

    #[test]
    #[should_panic(expected = "Element size 65536 is too big to be encoded using RLE encoding")]
    fn item_too_big() {
        run(|| async {
            drain_all(
                RoundRobinSubmission::new(
                    encoded(iter::once(vec![0xFF_u8; 65536]))
                        .join("\n")
                        .as_bytes(),
                )
                .into_byte_streams(3),
            )
            .await;
        });
    }

    #[test]
    fn empty() {
        run(|| async {
            let actual =
                drain_all(RoundRobinSubmission::new(&[] as &[u8]).into_byte_streams(3)).await;
            assert_eq!(vec!["", "", ""], actual);
        });
    }

    #[test]
    fn from_file() {
        run(|| async {
            let tmp_dir = TempDir::with_prefix("ipa-unit-test").unwrap();
            let file_path = tmp_dir.path().join("round-robin-sub.txt");
            let data = ["foo", "bar", "baz", "qux"];

            // add data to this file
            {
                let content = encoded(data.iter()).join("\n");
                let mut tmp_file = File::create(&file_path).unwrap();
                tmp_file.write_all(content.as_bytes()).unwrap();
                tmp_file.flush().unwrap();
            }

            // read from it through the stream
            let file = File::open(file_path).unwrap();
            let streams =
                RoundRobinSubmission(BufReader::new(file)).into_byte_streams(data.len() + 1);
            assert_eq!(
                vec!["foo", "bar", "baz", "qux", ""],
                drain_all(streams).await
            );
        });
    }

    async fn verify_one<I: AsRef<str> + Clone>(input: Vec<I>, count: usize) {
        assert!(count > 0);
        let data = encoded(input.iter().map(|v| v.as_ref().as_bytes())).join("\n");
        let streams = RoundRobinSubmission(data.as_bytes()).into_byte_streams(count);
        let mut expected = vec![String::new(); count];
        for (i, next) in input.into_iter().enumerate() {
            expected[i % count].push_str(next.as_ref());
        }
        assert_eq!(expected, drain_all(streams).await);
    }

    proptest! {
        #[test]
        fn proptest_round_robin(input: Vec<String>, count in 1_usize..953) {
            run(move || async move {
                verify_one(input, count).await;
            });
        }
    }
}
