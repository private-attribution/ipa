use std::{
    mem,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::Stream;
use pin_project::pin_project;

use crate::helpers::BytesStream;

/// An adaptor to buffer items coming from the upstream
/// [`BytesStream`](BytesStream) until the buffer is full, or the upstream is
/// done. This may need to be used when writing into HTTP streams as Hyper
/// does not provide any buffering functionality and we turn NODELAY on
#[pin_project]
pub struct BufferedBytesStream<S> {
    /// Inner stream to poll
    #[pin]
    inner: S,
    /// Buffer of bytes pending release
    buffer: Vec<u8>,
    /// Number of bytes released per single poll.
    /// All items except the last one are guaranteed to have
    /// exactly this number of bytes written to them.
    sz: usize,
}

impl<S> BufferedBytesStream<S> {
    fn new(inner: S, buf_size: NonZeroUsize) -> Self {
        Self {
            inner,
            buffer: Vec::with_capacity(buf_size.get()),
            sz: buf_size.get(),
        }
    }
}

impl<S: BytesStream> Stream for BufferedBytesStream<S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        fn take_next(buf: &mut Vec<u8>) -> Vec<u8> {
            mem::replace(buf, Vec::with_capacity(buf.len()))
        }

        let mut this = self.as_mut().project();
        loop {
            // If we are at capacity, return what we have
            if this.buffer.len() >= *this.sz {
                // if we have more than we need in the buffer, split it
                // otherwise, return the whole buffer to the reader
                let next = if this.buffer.len() > *this.sz {
                    this.buffer.drain(..*this.sz).collect()
                } else {
                    take_next(this.buffer)
                };
                break Poll::Ready(Some(Ok(Bytes::from(next))));
            }

            match this.inner.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    // Received next portion of data, buffer it
                    match item {
                        Ok(bytes) => {
                            this.buffer.extend(bytes);
                        }
                        Err(e) => {
                            break Poll::Ready(Some(Err(e)));
                        }
                    }
                }
                Poll::Ready(None) => {
                    // yield what we have because the upstream is done
                    let next = if this.buffer.is_empty() {
                        None
                    } else {
                        Some(Ok(Bytes::from(take_next(this.buffer))))
                    };

                    break Poll::Ready(next);
                }
                Poll::Pending => {
                    // we don't have enough data in the buffer (otherwise we wouldn't be here)
                    break Poll::Pending;
                }
            }
        }
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::{
        cmp::min,
        mem,
        num::NonZeroUsize,
        pin::Pin,
        sync::{Arc, Mutex},
        task,
        task::Poll,
    };

    use bytes::Bytes;
    use futures::{stream::TryStreamExt, FutureExt, Stream, StreamExt};
    use pin_project::pin_project;
    use proptest::{
        prop_compose, proptest,
        strategy::{Just, Strategy},
    };
    use task::Context;

    use crate::{
        error::BoxError, helpers::transport::stream::buffered::BufferedBytesStream,
        test_executor::run,
    };

    #[test]
    fn success() {
        run(|| async move {
            verify_success(infallible_stream(11, 2), 3).await;
            verify_success(infallible_stream(12, 3), 3).await;
            verify_success(infallible_stream(12, 5), 12).await;
            verify_success(infallible_stream(12, 12), 12).await;
            verify_success(infallible_stream(24, 12), 12).await;
            verify_success(infallible_stream(24, 12), 1).await;
        });
    }

    #[test]
    fn fails_on_first_error() {
        run(|| async move {
            let stream = fallible_stream(12, 3, 5);
            let mut buffered = BufferedBytesStream::new(stream, NonZeroUsize::try_from(2).unwrap());
            let mut buf = Vec::new();
            while let Some(next) = buffered.next().await {
                match next {
                    Ok(bytes) => {
                        assert_eq!(2, bytes.len());
                        buf.extend(bytes);
                    }
                    Err(_) => {
                        break;
                    }
                }
            }

            // we could only receive 2 bytes from the stream and here is why.
            // first read puts 3 bytes into the buffer and we take 2 bytes off it.
            // second read does not have sufficient bytes in the buffer, and we need
            // to read from the stream again. Next read results in an error and we
            // return it immediately
            assert_eq!(2, buf.len());
        });
    }

    #[test]
    fn pending() {
        let status = Arc::new(Mutex::new(vec![1, 2]));
        let stream = futures::stream::poll_fn({
            let status = Arc::clone(&status);
            move |_cx| {
                let mut vec = status.lock().unwrap();
                if vec.is_empty() {
                    Poll::Pending
                } else {
                    Poll::Ready(Some(Ok(Bytes::from(mem::take(&mut *vec)))))
                }
            }
        });

        let mut buffered = BufferedBytesStream::new(stream, NonZeroUsize::try_from(4).unwrap());
        let mut fut = std::pin::pin!(buffered.next());
        assert!(fut.as_mut().now_or_never().is_none());

        status.lock().unwrap().extend([3, 4]);
        let actual = fut.now_or_never().flatten().unwrap().unwrap();
        assert_eq!(Bytes::from(vec![1, 2, 3, 4]), actual);
    }

    async fn verify_success(input: TestStream, chunk_size: usize) {
        let total_size = input.total_size;
        assert!(total_size >= chunk_size);
        let expected = input.clone();
        let mut buffered = BufferedBytesStream::new(input, chunk_size.try_into().unwrap());

        let mut last_chunk_size = None;
        let mut actual = Vec::new();
        while let Ok(Some(bytes)) = buffered.try_next().await {
            assert!(bytes.len() <= chunk_size);
            // All chunks except the last one must be exactly of `chunk_size` size.
            if let Some(last) = last_chunk_size {
                assert_eq!(last, chunk_size);
            }
            last_chunk_size = Some(bytes.len());
            actual.extend(bytes);
        }

        // compare with what the original stream returned
        assert_eq!(actual.len(), total_size);
        let expected = expected
            .try_collect::<Vec<_>>()
            .await
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(expected, actual);
    }

    #[derive(Debug, Clone)]
    struct TestStream {
        total_size: usize,
        remaining: usize,
        chunk: usize,
    }

    #[pin_project]
    struct FallibleTestStream {
        #[pin]
        inner: TestStream,
        error_after: usize,
    }

    fn infallible_stream(total_size: usize, chunk: usize) -> TestStream {
        TestStream {
            total_size,
            remaining: total_size,
            chunk,
        }
    }

    fn fallible_stream(total_size: usize, chunk: usize, error_after: usize) -> FallibleTestStream {
        FallibleTestStream {
            inner: TestStream {
                total_size,
                remaining: total_size,
                chunk,
            },
            error_after,
        }
    }

    impl Stream for TestStream {
        type Item = Result<Bytes, BoxError>;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if self.remaining == 0 {
                return Poll::Ready(None);
            }
            let next_chunk_size = min(self.remaining, self.chunk);
            let next_chunk = (0..next_chunk_size)
                .map(|v| u8::try_from(v % 256).unwrap())
                .collect::<Vec<_>>();

            self.remaining -= next_chunk_size;
            Poll::Ready(Some(Ok(Bytes::from(next_chunk))))
        }
    }

    impl Stream for FallibleTestStream {
        type Item = Result<Bytes, BoxError>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let mut this = self.project();
            match this.inner.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(bytes))) => {
                    if this.inner.total_size - this.inner.remaining >= *this.error_after {
                        Poll::Ready(Some(Err("error".into())))
                    } else {
                        Poll::Ready(Some(Ok(bytes)))
                    }
                }
                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    prop_compose! {
        fn arb_infallible_stream(max_size: u16)
                    (total_size in 1..max_size)
                    (total_size in Just(total_size), chunk in 1..total_size)
                    -> TestStream {
            TestStream {
                total_size: total_size as usize,
                remaining: total_size as usize,
                chunk: chunk as usize,
            }
        }
    }

    fn stream_and_chunk() -> impl Strategy<Value = (TestStream, usize)> {
        arb_infallible_stream(24231).prop_flat_map(|stream| {
            let len = stream.total_size;
            (Just(stream), 1..len)
        })
    }

    proptest! {
        #[test]
        fn proptest_success((stream, chunk) in stream_and_chunk()) {
            run(move || async move {
                verify_success(stream, chunk).await;
            });
        }
    }
}
