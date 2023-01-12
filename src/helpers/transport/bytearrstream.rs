use crate::error::BoxError;
use axum::extract::BodyStream;
use futures::{ready, Stream};
use hyper::body::Bytes;
use pin_project::pin_project;
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

/// TODO: Right now, this implementation assumes that each `Item` of the stream is exactly the size
///       of 1 [`Field`]. However, this is very inefficient because `Bytes` itself takes up 32 bytes
///       on its own. We should rethink this at a later date to output "chunks" that are multiples
///       of `size_in_bytes` to be more efficient.
/// Wraps a [`BodyStream`] and produce a new stream that has chunks of exactly size `size_in_bytes`.
/// # Errors
/// If the downstream body is not a multiple of `size_in_bytes`.
#[derive(Debug)]
#[pin_project]
pub struct ByteArrStream {
    #[pin]
    body: BodyStream,
    size_in_bytes: u32,
    buffered_size: u32,
    buffered: VecDeque<Bytes>,
}

impl ByteArrStream {
    /// # Panics
    /// if `size_in_bytes` is 0
    #[must_use]
    pub fn new(body: BodyStream, size_in_bytes: u32) -> Self {
        assert_ne!(size_in_bytes, 0);
        Self {
            body,
            size_in_bytes,
            buffered_size: 0,
            buffered: VecDeque::new(),
        }
    }

    /// returns [`Bytes`] of `size_in_bytes` length from the buffered chunks. Returns [`None`] if
    /// there are less than `size_in_bytes` bytes in the buffer
    fn pop_front(&mut self) -> Option<Bytes> {
        // not enough bytes buffered
        if self.buffered_size < self.size_in_bytes {
            None
        } else if self.buffered[0].len() > self.size_in_bytes as usize {
            // if the first buffer is large enough, simply split it in-place.
            // This is O(1) operation, and should be true majority of the time, assuming large size
            // buffers
            let out_bytes = self.buffered[0].split_to(self.size_in_bytes as usize);
            self.buffered_size -= self.size_in_bytes;
            Some(out_bytes)
        } else {
            // First buffer is too small, so we need to take across buffers.
            // Will require a memcopy of u8's across buffers in order to create 1 contiguous buffer
            // to return.
            // Removes expended buffers after taking

            let mut out_bytes = Vec::with_capacity(self.size_in_bytes as usize);
            // this must loop through the bytes buffers because we don't know how many buffers will
            // be needed to fulfill `size_in_bytes`. e.g. if every buffer had length 1, we'd need to
            // visit `size_in_bytes` buffers in order to fill `out_bytes`
            loop {
                let remaining_bytes = out_bytes.capacity() - out_bytes.len();
                if remaining_bytes == 0 {
                    break;
                }
                // current `buffer` has more bytes than needed
                if self.buffered[0].len() > remaining_bytes {
                    let remaining = self.buffered[0].split_to(remaining_bytes);
                    out_bytes.extend_from_slice(&remaining);
                } else {
                    // current `buffer` has <= bytes needed, remove and append to out_bytes
                    out_bytes.extend_from_slice(&self.buffered.pop_front().unwrap());
                }
            }
            // reduce size of total buffers accordingly
            self.buffered_size -= self.size_in_bytes;
            Some(Bytes::from(out_bytes))
        }
    }

    fn pop_remaining(&mut self) -> Option<Bytes> {
        // if there are 2 or more chunks left, append them
        if self.buffered.len() > 1 {
            let mut out_bytes = Vec::with_capacity(usize::try_from(self.buffered_size).unwrap());
            while let Some(buffer) = self.buffered.pop_front() {
                out_bytes.extend_from_slice(&buffer);
            }
            self.buffered_size = 0;
            Some(Bytes::from(out_bytes))
            // if there is 1 or 0 chunks left, just return that
        } else {
            self.buffered_size = 0;
            self.buffered.pop_front()
        }
    }

    fn push_back(&mut self, buf: Bytes) {
        self.buffered_size += u32::try_from(buf.len()).unwrap();
        self.buffered.push_back(buf);
    }
}

impl Stream for ByteArrStream {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            // if we have enough bytes buffered, return them
            if let Some(bytes) = self.pop_front() {
                return Poll::Ready(Some(Ok(bytes)));
            }
            // if we need more bytes, poll the body
            let mut this = self.as_mut().project();
            match ready!(this.body.as_mut().poll_next(cx)) {
                // if body is expended, but we have some bytes leftover, just return what is left
                // TODO: this is hacky because it doesn't ensure alignment
                None if *this.buffered_size > 0 => {
                    return Poll::Ready(self.pop_remaining().map(Ok));
                }

                // if body is finished, this stream is finished
                None => return Poll::Ready(None),

                // if body produces error, forward the error
                Some(Err(err)) => {
                    return Poll::Ready(Some(Err(std::io::Error::new::<BoxError>(
                        std::io::ErrorKind::UnexpectedEof,
                        err.into(),
                    ))));
                }

                // if body has more bytes, push it into the buffer and loop
                Some(Ok(bytes)) => {
                    self.push_back(bytes);
                }
            }
        }
    }
}

// TODO: these tests have been ignored due to the multiple TODO's above
#[cfg(test)]
mod test {
    use super::*;
    use crate::ff::{self, Field, FieldType};
    use axum::{
        extract::{rejection::BodyAlreadyExtracted, FromRequest, RequestParts},
        http::{HeaderMap, Request},
    };
    use hyper::{body::HttpBody, Body};

    async fn from_slice(
        slice: &[u8],
        field_type: FieldType,
    ) -> Result<ByteArrStream, BodyAlreadyExtracted> {
        let b = Body::from(Bytes::from(slice.to_owned()));
        let mut req_parts = RequestParts::new(
            Request::post(format!("/example?field_type={field_type:?}"))
                .body(b)
                .unwrap(),
        );
        let body_stream = BodyStream::from_request(&mut req_parts).await?;
        Ok(ByteArrStream::new(body_stream, field_type.size_in_bytes()))
    }

    /// Simple body that represents a stream of `Bytes` chunks.
    /// Cannot use [`StreamBody`] because it has an error type of `axum::error::Error`, whereas
    /// [`BodyStream`] expects a `hyper::Error`. Yes, this is confusing.
    #[pin_project]
    struct ChunkedBody<St>(#[pin] St);

    impl<St: Stream<Item = Result<Bytes, hyper::Error>>> HttpBody for ChunkedBody<St> {
        type Data = Bytes;
        type Error = hyper::Error;

        fn poll_data(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Self::Data, Self::Error>>> {
            self.as_mut().project().0.poll_next(cx)
        }

        fn poll_trailers(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Result<Option<HeaderMap>, Self::Error>> {
            Poll::Ready(Ok(None))
        }
    }

    async fn from_chunked<'a, Item: IntoIterator<Item = &'a u8>, I: IntoIterator<Item = Item>>(
        it: I,
        field_type: FieldType,
    ) -> ByteArrStream {
        let chunks = it
            .into_iter()
            .map(|chunk| Ok(Bytes::from(chunk.into_iter().copied().collect::<Vec<_>>())))
            .collect::<Vec<_>>();

        let mut req_parts = RequestParts::new(
            Request::post("/")
                .body(ChunkedBody(futures::stream::iter(chunks)))
                .unwrap(),
        );
        let body_stream = req_parts.extract::<BodyStream>().await.unwrap();
        ByteArrStream::new(body_stream, field_type.size_in_bytes())
    }

    mod unit_test {
        use super::*;
        use futures_util::{StreamExt, TryStreamExt};

        #[tokio::test]
        #[ignore]
        async fn byte_arr_stream_produces_bytes_fp2() {
            let vec = vec![3; 10];
            let stream = from_slice(&vec, FieldType::Fp2).await.unwrap();
            let collected = stream.try_collect::<Vec<_>>().await.unwrap();
            for (expected, got) in vec.chunks(ff::Fp2::SIZE_IN_BYTES as usize).zip(collected) {
                assert_eq!(expected, got.as_ref());
            }
        }

        #[tokio::test]
        #[ignore]
        async fn byte_arr_stream_produces_bytes_fp32_bit_prime() {
            const ARR_SIZE: usize = 20;
            let vec = vec![7; ARR_SIZE * 10];
            let stream = from_slice(&vec, FieldType::Fp32BitPrime).await.unwrap();
            let collected = stream.try_collect::<Vec<_>>().await.unwrap();
            for (expected, got) in vec
                .chunks(ff::Fp32BitPrime::SIZE_IN_BYTES as usize)
                .zip(collected)
            {
                assert_eq!(expected, got.as_ref());
            }
        }

        #[tokio::test]
        #[ignore]
        async fn byte_arr_stream_fails_on_invalid_size() {
            const ARR_SIZE: usize = 2;
            // 1 extra byte
            let vec = vec![4u8; ARR_SIZE * (ff::Fp32BitPrime::SIZE_IN_BYTES as usize) + 1];
            let mut stream = from_slice(&vec, FieldType::Fp32BitPrime).await.unwrap();

            // valid values
            for _ in 0..ARR_SIZE {
                stream.next().await;
            }
            let failed = stream.next().await;
            let failed_kind = failed.map(|res| res.map_err(|err| err.kind()));
            assert_eq!(
                failed_kind,
                Some(Err(std::io::ErrorKind::WriteZero)),
                "actually got {failed_kind:?}"
            );
        }

        // this test confirms that `ByteArrStream` doesn't buffer more than it needs to as it produces
        // bytes
        #[tokio::test]
        #[ignore]
        async fn byte_arr_stream_buffers_optimally() {
            const ARR_SIZE: usize = 20;
            const CHUNK_SIZE: usize = 3;
            let vec = vec![7u8; ARR_SIZE * (ff::Fp32BitPrime::SIZE_IN_BYTES as usize)];
            let mut byte_arr_stream =
                from_chunked(vec.chunks(CHUNK_SIZE), FieldType::Fp32BitPrime).await;
            assert_eq!(byte_arr_stream.buffered.len(), 0);
            for expected_chunk in vec.chunks(ff::Fp32BitPrime::SIZE_IN_BYTES as usize) {
                let n = byte_arr_stream.next().await.unwrap().unwrap();
                // `ByteArrStream` outputs correct value
                assert_eq!(expected_chunk, &n);
                // `ByteArrStream` only contains at most 1 buffered chunk
                assert!(byte_arr_stream.buffered.len() <= 1);
                // `ByteArrStream` only contains at most `CHUNK_SIZE` values in its buffer
                assert!(byte_arr_stream.buffered_size <= u32::try_from(CHUNK_SIZE).unwrap());
            }
        }

        // this test confirms that `ByteArrStream` doesn't call on the buffer at all if the existing
        // one is sufficient to produce bytes
        // for the purposes of this test, assumes that chunks are of uniform size (until the last chunk)
        #[tokio::test]
        #[ignore]
        async fn byte_arr_stream_buffers_only_when_needed() {
            const ARR_SIZE: usize = 20;
            const CHUNK_SIZE: u32 = 9;
            let vec = vec![7u8; ARR_SIZE * (ff::Fp32BitPrime::SIZE_IN_BYTES as usize)];
            let mut byte_arr_stream =
                from_chunked(vec.chunks(CHUNK_SIZE as usize), FieldType::Fp32BitPrime).await;
            assert_eq!(byte_arr_stream.buffered.len(), 0);

            // number of bytes pushed downstream
            let mut num_downstream = 0;
            // number of bytes pulled from upstream
            let mut num_upstream =
                u32::try_from(ARR_SIZE).unwrap() * ff::Fp32BitPrime::SIZE_IN_BYTES;
            // expected size of buffer inside
            let mut expected_size = 0;
            for expected_n in vec.chunks(ff::Fp32BitPrime::SIZE_IN_BYTES as usize) {
                // check that bytes are as expected
                let n = byte_arr_stream.next().await.unwrap().unwrap();
                assert_eq!(expected_n, &n);
                assert!(byte_arr_stream.buffered.len() <= 1);

                // sent Fp32BitPrime downstream
                num_downstream += ff::Fp32BitPrime::SIZE_IN_BYTES;
                // remove those bytes from buffer
                expected_size -= i32::try_from(ff::Fp32BitPrime::SIZE_IN_BYTES).unwrap();
                // if no more bytes in buffer, get more
                if expected_size < 0 {
                    // enough bytes upstream to pull a full chunk
                    if CHUNK_SIZE < num_upstream {
                        num_upstream -= CHUNK_SIZE;
                        expected_size += i32::try_from(CHUNK_SIZE).unwrap();
                    } else {
                        // last chunk from upstream may be < full chunk size
                        expected_size += i32::try_from(num_upstream).unwrap();
                        num_upstream = 0;
                    }
                }
                assert_eq!(
                    byte_arr_stream.buffered_size,
                    u32::try_from(expected_size).unwrap()
                );
            }
            assert_eq!(
                num_downstream,
                u32::try_from(ARR_SIZE).unwrap() * ff::Fp32BitPrime::SIZE_IN_BYTES
            );
        }
    }

    mod prop_test {
        use super::*;
        use futures::TryStreamExt;
        use proptest::prelude::*;
        use rand::{rngs::StdRng, SeedableRng};

        prop_compose! {
            fn arb_aligned_bytes(field_type: FieldType, max_len: u32)
                                (field_type in Just(field_type), len in 1..(max_len as usize))
                                (vec in prop::collection::vec(any::<u8>(), len * field_type.size_in_bytes() as usize))
            -> Vec<u8> {
                vec
            }
        }

        fn random_chunks<R: RngCore>(mut slice: &[u8], rng: &mut R) -> Vec<Vec<u8>> {
            let mut output = Vec::new();
            loop {
                let len = slice.len();
                let idx = rng.gen_range(1..len);
                match idx {
                    split_idx if split_idx == len - 1 => {
                        output.push(slice.to_vec());
                        break;
                    }
                    split_idx => {
                        let (next_chunk, remaining) = slice.split_at(split_idx);
                        output.push(next_chunk.to_vec());
                        slice = remaining;
                    }
                }
            }
            output
        }

        fn arb_chunked_body<R: RngCore>(
            vec: &[u8],
            field_type: FieldType,
            rng: &mut R,
        ) -> ByteArrStream {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(from_chunked(&random_chunks(vec, rng), field_type))
        }

        prop_compose! {
            fn arb_expected_and_chunked_body(field_type: FieldType, max_len: u32)
                                            (expected in arb_aligned_bytes(field_type, max_len), seed in any::<u64>())
            -> (Vec<u8>, ByteArrStream, u64) {
                (expected.clone(), arb_chunked_body(&expected, field_type, &mut StdRng::seed_from_u64(seed)), seed)
            }
        }

        proptest::proptest! {
            #[test]
            #[ignore]
            fn test_byte_arr_stream_works_with_any_chunks(
                (expected_bytes, chunked_bytes, _seed) in arb_expected_and_chunked_body(FieldType::Fp32BitPrime, 100)
            ) {
                tokio::runtime::Runtime::new().unwrap().block_on(async {
                    let collected = chunked_bytes.try_collect::<Vec<_>>().await.unwrap();
                    for (expected, got) in expected_bytes.chunks(ff::Fp32BitPrime::SIZE_IN_BYTES as usize).zip(collected) {
                        assert_eq!(expected, got.as_ref());
                    }
                });
            }
        }
    }
}
