use crate::error::BoxError;
use axum::extract::BodyStream;
use futures::{ready, Stream};
use hyper::body::Bytes;
use pin_project::pin_project;
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

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

    /// returns [`Bytes`] in multiples of `size_in_bytes` length from the buffered chunks. Returns
    /// [`None`] if there are less than `size_in_bytes` bytes in the buffer
    fn pop_front(&mut self) -> Option<Bytes> {
        // not enough bytes buffered
        if self.buffered_size < self.size_in_bytes {
            None
        } else if self.buffered[0].len() >= self.size_in_bytes as usize {
            // split off as much of the first buffer as can be aligned. This is O(1) operation,
            // and should occur once per buffer, assuming buffers are typically larger than
            // `size_in_bytes`
            let buff_len = u32::try_from(self.buffered[0].len()).unwrap();
            let num_aligned = buff_len / self.size_in_bytes;
            let out_count = num_aligned * self.size_in_bytes;
            self.buffered_size -= out_count;

            // if buffer is exactly aligned with `size_in_bytes`, remove and return it; otherwise,
            // just split as much as can be aligned.
            let res = self.buffered[0].split_to(usize::try_from(out_count).unwrap());
            if self.buffered[0].is_empty() {
                self.buffered.pop_front();
            }
            Some(res)
        } else {
            // first buffer is smaller than `size_in_bytes`, so will need to combine bytes across
            // buffers. Will require a memcpy of u8's across buffers to create 1 contiguous aligned
            // chunk to return. Should occur at most once per buffer, assuming buffers are typically
            // larger than `size_in_bytes`
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
            self.buffered_size -= u32::try_from(out_bytes.len()).unwrap();
            Some(Bytes::from(out_bytes))
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
                // if body is expended, but we have some bytes leftover, error due to misaligned
                // output
                None if *this.buffered_size > 0 => {
                    return Poll::Ready(Some(Err(std::io::Error::new::<BoxError>(
                        std::io::ErrorKind::WriteZero,
                        format!(
                            "{} bytes remaining, but needed {} bytes to align with expected output",
                            this.buffered_size, this.size_in_bytes
                        )
                        .into(),
                    ))));
                }

                // if body is finished with no more bytes remaining, this stream is finished.
                // equivalent of `None if *this.buffered_size == 0 =>`
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
        size_in_bytes: u32,
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
        ByteArrStream::new(body_stream, size_in_bytes)
    }

    mod unit_test {
        use super::*;
        use futures_util::{StreamExt, TryStreamExt};

        #[tokio::test]
        async fn byte_arr_stream_produces_bytes_fp2() {
            let vec = vec![3; 10];
            let stream = from_slice(&vec, FieldType::Fp2).await.unwrap();
            let collected = stream.try_collect::<Vec<_>>().await.unwrap();

            // since `from_slice` chunks by the entire slice, expect the entire slice in `collected`
            assert_eq!(collected.len(), 1);
            assert_eq!(collected[0].to_vec(), vec);
        }

        #[tokio::test]
        async fn byte_arr_stream_produces_bytes_fp32_bit_prime() {
            const ARR_SIZE: usize = 20;
            let vec = vec![7; ARR_SIZE * 10];
            let stream = from_slice(&vec, FieldType::Fp32BitPrime).await.unwrap();
            let collected = stream.try_collect::<Vec<_>>().await.unwrap();

            // since `from_slice` chunks by the entire slice, expect the entire slice in `collected`
            assert_eq!(collected.len(), 1);
            assert_eq!(collected[0].to_vec(), vec);
        }

        #[tokio::test]
        async fn byte_arr_stream_fails_on_invalid_size() {
            const ARR_SIZE: usize = 5;
            // 1 extra byte
            let vec = vec![4u8; ARR_SIZE * (ff::Fp32BitPrime::SIZE_IN_BYTES as usize) + 1];
            let mut stream = from_slice(&vec, FieldType::Fp32BitPrime).await.unwrap();

            // valid values
            let n = stream.next().await;
            assert!(n.is_some());
            let n = n.unwrap();
            assert!(n.is_ok());
            let n = n.unwrap();
            assert_eq!(
                n.as_ref(),
                &vec[..ARR_SIZE * (ff::Fp32BitPrime::SIZE_IN_BYTES as usize)]
            );

            // invalid remainder
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
        async fn byte_arr_stream_buffers_optimally() {
            const ARR_SIZE: usize = 20;
            const CHUNK_SIZE: usize = 3;
            let vec = vec![7u8; ARR_SIZE * (ff::Fp32BitPrime::SIZE_IN_BYTES as usize)];
            let mut byte_arr_stream =
                from_chunked(vec.chunks(CHUNK_SIZE), ff::Fp32BitPrime::SIZE_IN_BYTES).await;
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

        // checks that the `ByteArrStream` will return chunks that are multiples of `SIZE_IN_BYTES`
        #[tokio::test]
        async fn returns_multiples() {
            const ARR_SIZE: usize = 201;
            const SIZE_IN_BYTES: u32 = ff::Fp32BitPrime::SIZE_IN_BYTES;
            const CHUNK_SIZE: usize = SIZE_IN_BYTES as usize * 4;
            let vec = vec![8u8; ARR_SIZE * usize::try_from(SIZE_IN_BYTES).unwrap()];
            let mut byte_arr_stream = from_chunked(vec.chunks(CHUNK_SIZE), SIZE_IN_BYTES).await;
            let mut seen_count = 0;
            loop {
                let next_chunk = byte_arr_stream.next().await.unwrap().unwrap();
                let chunk_len = next_chunk.len();
                if chunk_len != CHUNK_SIZE {
                    assert_eq!(
                        chunk_len,
                        ARR_SIZE * usize::try_from(SIZE_IN_BYTES).unwrap() - seen_count
                    );
                    break;
                }
                seen_count += chunk_len;
            }
            assert!(byte_arr_stream.next().await.is_none());
        }

        // checks that `ByteArrStream` can handles unaligned chunk sizes
        #[tokio::test]
        async fn returns_multiples_unaligned() {
            const ARR_SIZE: usize = 200;
            const SIZE_IN_BYTES: u32 = ff::Fp32BitPrime::SIZE_IN_BYTES * 2;
            const CHUNK_SIZE: usize = SIZE_IN_BYTES as usize * 5 + 7;
            let vec = vec![9u8; ARR_SIZE * usize::try_from(SIZE_IN_BYTES).unwrap()];
            let mut byte_arr_stream = from_chunked(vec.chunks(CHUNK_SIZE), SIZE_IN_BYTES).await;

            let mut seen_count = 0;
            let mut more_than_one = false;
            while let Some(Ok(bytes)) = byte_arr_stream.next().await {
                assert_eq!(bytes.len() % usize::try_from(SIZE_IN_BYTES).unwrap(), 0);
                let count = bytes.len() / usize::try_from(SIZE_IN_BYTES).unwrap();
                if count > 1 {
                    more_than_one = true;
                }
                seen_count += count;
            }
            assert_eq!(seen_count, ARR_SIZE);
            assert!(more_than_one);
        }
    }

    mod prop_test {
        use super::*;
        use futures::TryStreamExt;
        use proptest::prelude::*;
        use rand::{rngs::StdRng, SeedableRng};

        prop_compose! {
            fn arb_size_in_bytes(field_type: FieldType, max_multiplier: u32)
                                (multiplier in 1..max_multiplier)
            -> u32 {
                field_type.size_in_bytes() * multiplier
            }
        }

        prop_compose! {
            fn arb_aligned_bytes(size_in_bytes: u32, max_len: u32)
                                (size_in_bytes in Just(size_in_bytes), len in 1..(max_len as usize))
                                (vec in prop::collection::vec(any::<u8>(), len * size_in_bytes as usize))
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
            size_in_bytes: u32,
            rng: &mut R,
        ) -> ByteArrStream {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(from_chunked(&random_chunks(vec, rng), size_in_bytes))
        }

        prop_compose! {
            fn arb_expected_and_chunked_body(field_type: FieldType, max_multiplier: u32, max_len: u32)
                                            (size_in_bytes in arb_size_in_bytes(field_type, max_multiplier), max_len in Just(max_len))
                                            (size_in_bytes in Just(size_in_bytes), expected in arb_aligned_bytes(size_in_bytes, max_len), seed in any::<u64>())
            -> (u32, Vec<u8>, ByteArrStream, u64) {
                (size_in_bytes, expected.clone(), arb_chunked_body(&expected, size_in_bytes, &mut StdRng::seed_from_u64(seed)), seed)
            }
        }

        proptest::proptest! {
            #[test]
            fn test_byte_arr_stream_works_with_any_chunks(
                (size_in_bytes, expected_bytes, chunked_bytes, _seed) in arb_expected_and_chunked_body(FieldType::Fp32BitPrime, 30, 100)
            ) {
                tokio::runtime::Runtime::new().unwrap().block_on(async {
                    // flatten the chunks to compare with expected
                    let collected_bytes = chunked_bytes
                        .try_collect::<Vec<_>>()
                        .await
                        .unwrap()
                        .into_iter()
                        .flat_map(|bytes| {
                            assert_eq!(bytes.len() % usize::try_from(size_in_bytes).unwrap(), 0);
                            bytes.to_vec()
                        })
                        .collect::<Vec<_>>();

                    assert_eq!(collected_bytes, expected_bytes);
                });
            }
        }
    }
}
