use crate::{error::BoxError, ff::Serializable, helpers::BytesStream};
use bytes::Bytes;
use futures::{
    stream::{iter, once, FusedStream, Iter, Map, Once},
    Stream, StreamExt,
};
use futures_util::stream::Fuse;
use pin_project::pin_project;
use std::{
    cmp::max,
    collections::VecDeque,
    fmt::{Debug, Formatter},
    future::Ready,
    io,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};
use typenum::{Unsigned, U2};

#[derive(Debug)]
pub struct BufDeque {
    buffered_size: usize,
    buffered: VecDeque<Bytes>,
}

impl BufDeque {
    fn new() -> Self {
        Self {
            buffered_size: 0,
            buffered: VecDeque::new(),
        }
    }

    /// Returns the total amount of buffered data
    #[cfg(all(test, not(feature = "shuttle")))]
    fn len(&self) -> usize {
        self.buffered_size
    }

    /// Returns the amount of contiguous data available
    fn contiguous_len(&self) -> usize {
        self.buffered.front().map_or(0, Bytes::len)
    }

    /// Read bytes from the buffer.
    ///
    /// Returns [`Bytes`] with length `len` from the buffered data. Returns [`None`] if
    /// there are less than `len` bytes in the buffer, or if `len` is zero.
    fn read_bytes(&mut self, len: usize) -> Option<Bytes> {
        // not enough bytes buffered
        if len == 0 || self.buffered_size < len {
            None
        } else if self.buffered[0].len() >= len {
            self.buffered_size -= len;
            let res = self.buffered[0].split_to(len);
            if self.buffered[0].is_empty() {
                self.buffered.pop_front();
            }
            Some(res)
        } else {
            // first buffer is smaller than `len`, so will need to combine bytes across
            // buffers. Will require a memcpy of u8's across buffers to create 1 contiguous aligned
            // chunk to return. Should occur at most once per buffer, assuming buffers are typically
            // larger than `len`
            let mut out_bytes = Vec::with_capacity(len);

            // this must loop through the bytes buffers because we don't know how many buffers will
            // be needed to fulfill `len`. e.g. if every buffer had length 1, we'd need to
            // visit `len` buffers in order to fill `out_bytes`
            loop {
                let remaining_bytes = out_bytes.capacity() - out_bytes.len();
                if remaining_bytes == 0 {
                    break;
                }
                // current buffer has more bytes than needed
                if self.buffered[0].len() > remaining_bytes {
                    let remaining = self.buffered[0].split_to(remaining_bytes);
                    out_bytes.extend_from_slice(&remaining);
                } else {
                    // current `buffer` has <= bytes needed, remove and append to out_bytes
                    out_bytes.extend_from_slice(&self.buffered.pop_front().unwrap());
                }
            }
            // reduce size of total buffers accordingly
            self.buffered_size -= out_bytes.len();
            Some(Bytes::from(out_bytes))
        }
    }

    /// Deserialize fixed-length items from the buffer.
    ///
    /// Deserializes `count` items of fixed-length-[`Serializable`] type `T` from the stream.
    /// Returns `None` if there are less than `count` items available, or if `count` is zero.
    fn read_multi<T: Serializable>(&mut self, count: usize) -> Option<Vec<T>> {
        self.read_bytes(count * T::Size::USIZE).map(|bytes| {
            bytes
                .chunks(T::Size::USIZE)
                .map(|bytes| T::deserialize(bytes.into()))
                .collect()
        })
    }

    /// Deserialize fixed-length items from the buffer.
    ///
    /// Deserializes a single instance of fixed-length-[`Serializable`] type `T` from the stream.
    /// Returns `None` if there is insufficient data available.
    fn read<T: Serializable>(&mut self) -> Option<T> {
        self.read_bytes(T::Size::USIZE)
            .map(|bytes| T::deserialize(bytes.as_ref().into()))
    }

    /// Update the buffer with the result of polling a stream.
    ///
    /// Returns one of the following:
    ///  * `None`, if data from the stream was appended to the buffer.
    ///  * `Some(None)`, if the stream finished cleanly.
    ///  * `Some(error)`, if the stream errored.
    #[allow(clippy::option_option)] // TODO: create an enum for the return type
    fn extend(&mut self, bytes: Option<Result<Bytes, BoxError>>) -> Option<Option<io::Error>> {
        match bytes {
            // if body is expended, but we have some bytes leftover, error due to misaligned
            // output
            None if self.buffered_size > 0 => Some(Some(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("stream terminated with {} extra bytes", self.buffered_size),
            ))),

            // if body is finished with no more bytes remaining, this stream is finished.
            // equivalent of `None if self.buffered_size == 0 =>`
            None => Some(None),

            // if body produces error, forward the error
            Some(Err(err)) => Some(Some(io::Error::new(io::ErrorKind::UnexpectedEof, err))),

            // if body has more bytes, push it into the buffer
            Some(Ok(bytes)) => {
                self.buffered_size += bytes.len();
                self.buffered.push_back(bytes);
                None
            }
        }
    }
}

/// Parse a [`Stream`] of [`Bytes`] into a stream of records of some
/// fixed-length-[`Serializable`] type `T`.
#[pin_project]
pub struct RecordsStream<T, S>
where
    S: BytesStream,
    T: Serializable,
{
    // Our implementation of `poll_next` turns a `None` from the inner stream into `Some(Err(_))` if
    // there is extra trailing data. We do not expect to be polled again after that happens, but
    // doing so is allowed by the `Stream` trait, so we need a fuse to ensure we don't poll the
    // inner stream after it finishes.
    #[pin]
    stream: Fuse<S>,
    buffer: BufDeque,
    phantom_data: PhantomData<T>,
}

impl<T, S> RecordsStream<T, S>
where
    S: BytesStream,
    T: Serializable,
{
    #[must_use]
    pub fn new(stream: S) -> Self {
        Self {
            stream: stream.fuse(),
            buffer: BufDeque::new(),
            phantom_data: PhantomData,
        }
    }
}

impl<T, S> Stream for RecordsStream<T, S>
where
    S: BytesStream,
    T: Serializable,
{
    type Item = Result<Vec<T>, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        loop {
            let count = max(1, this.buffer.contiguous_len() / T::Size::USIZE);
            if let Some(items) = this.buffer.read_multi(count) {
                return Poll::Ready(Some(Ok(items)));
            }

            // We need more data, poll the stream
            let Poll::Ready(polled_item) = this.stream.as_mut().poll_next(cx) else {
                return Poll::Pending;
            };

            if let Some(item) = this.buffer.extend(polled_item) {
                return Poll::Ready(item.map(Err));
            }
        }
    }
}

impl<T, S> FusedStream for RecordsStream<T, S>
where
    S: BytesStream,
    T: Serializable,
{
    fn is_terminated(&self) -> bool {
        self.stream.is_terminated()
    }
}

impl<T, S> Debug for RecordsStream<T, S>
where
    S: BytesStream,
    T: Serializable,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RecordsStream {{ stream: <Stream>, buffer: {:?} }}",
            self.buffer,
        )
    }
}

impl<T: Serializable> From<Vec<u8>> for RecordsStream<T, Once<Ready<Result<Bytes, BoxError>>>> {
    fn from(vec: Vec<u8>) -> Self {
        RecordsStream::new(once(std::future::ready(Ok(Bytes::from(vec)))))
    }
}

impl<T, Buf, I> From<I>
    for RecordsStream<T, Map<Iter<I::IntoIter>, fn(Buf) -> Result<Bytes, BoxError>>>
where
    T: Serializable,
    Buf: Into<Bytes>,
    I: IntoIterator<Item = Buf>,
    <I as IntoIterator>::IntoIter: Send,
{
    fn from(value: I) -> Self {
        RecordsStream::new(iter(value.into_iter()).map(|buf| Ok(buf.into())))
    }
}

struct Length(u16);

impl Serializable for Length {
    type Size = U2;

    fn serialize(&self, buf: &mut generic_array::GenericArray<u8, Self::Size>) {
        *buf.as_mut() = self.0.to_le_bytes();
    }

    fn deserialize(buf: &generic_array::GenericArray<u8, Self::Size>) -> Self {
        Self(u16::from_le_bytes(<[u8; 2]>::from(*buf)))
    }
}

impl From<Length> for usize {
    fn from(value: Length) -> Self {
        value.0.into()
    }
}

/// Parse a [`Stream`] of [`Bytes`] into a stream of records of some variable-length type `T`.
#[pin_project]
pub struct LengthDelimitedStream<T, S>
where
    S: BytesStream,
    T: TryFrom<Bytes>,
{
    // Our implementation of `poll_next` turns a `None` from the inner stream into `Some(Err(_))` if
    // there is extra trailing data. We do not expect to be polled again after that happens, but
    // doing so is allowed by the `Stream` trait, so we need a fuse to ensure we don't poll the
    // inner stream after it finishes.
    #[pin]
    stream: Fuse<S>,
    buffer: BufDeque,
    pending_len: Option<usize>,
    phantom_data: PhantomData<T>,
}

impl<T, S> LengthDelimitedStream<T, S>
where
    S: BytesStream,
    T: TryFrom<Bytes>,
{
    #[must_use]
    pub fn new(stream: S) -> Self {
        Self {
            stream: stream.fuse(),
            buffer: BufDeque::new(),
            pending_len: None,
            phantom_data: PhantomData,
        }
    }
}

const ESTIMATED_AVERAGE_REPORT_SIZE: usize = 80; // TODO: confirm/adjust

impl<T, S> Stream for LengthDelimitedStream<T, S>
where
    S: BytesStream,
    T: TryFrom<Bytes>,
    <T as TryFrom<Bytes>>::Error: Into<BoxError>,
{
    type Item = Result<Vec<T>, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        let mut items =
            Vec::with_capacity(this.buffer.contiguous_len() / ESTIMATED_AVERAGE_REPORT_SIZE);
        loop {
            if this.pending_len.is_none() {
                if let Some(len) = this.buffer.read::<Length>().map(Into::into) {
                    *this.pending_len = Some(len);
                }
            }

            if let Some(len) = *this.pending_len {
                if let Some(bytes) = this.buffer.read_bytes(len) {
                    *this.pending_len = None;
                    match T::try_from(bytes) {
                        Ok(item) => items.push(item),
                        // TODO: Since we need to recover from individual invalid reports, we
                        // probably need `type Item = Result<Vec<Result<T, ?>>, io::Error>`, and we
                        // need to flush (rather than discard) pending `items` from before the
                        // error.
                        Err(err) => {
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                err,
                            ))))
                        }
                    }
                }
            }

            if !items.is_empty() {
                // If we have something to return, do so.
                return Poll::Ready(Some(Ok(items)));
            }

            // We need more data, poll the stream.
            let Poll::Ready(polled_item) = this.stream.as_mut().poll_next(cx) else {
                return Poll::Pending;
            };

            if let Some(item) = this.buffer.extend(polled_item) {
                return Poll::Ready(item.map(Err));
            }
        }
    }
}

impl<T, S> FusedStream for LengthDelimitedStream<T, S>
where
    S: BytesStream,
    T: TryFrom<Bytes>,
    <T as TryFrom<Bytes>>::Error: Into<BoxError>,
{
    fn is_terminated(&self) -> bool {
        self.stream.is_terminated()
    }
}

impl<T, S> Debug for LengthDelimitedStream<T, S>
where
    S: BytesStream,
    T: TryFrom<Bytes>,
    <T as TryFrom<Bytes>>::Error: Into<BoxError>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LengthDelimitedStream {{ stream: <Stream>, buffer: {:?} }}",
            self.buffer,
        )
    }
}

impl<T> From<Vec<u8>> for LengthDelimitedStream<T, Once<Ready<Result<Bytes, BoxError>>>>
where
    T: TryFrom<Bytes>,
    <T as TryFrom<Bytes>>::Error: Into<BoxError>,
{
    fn from(vec: Vec<u8>) -> Self {
        LengthDelimitedStream::new(once(std::future::ready(Ok(Bytes::from(vec)))))
    }
}

impl<T, Buf, I> From<I>
    for LengthDelimitedStream<T, Map<Iter<I>, fn(Buf) -> Result<Bytes, BoxError>>>
where
    T: TryFrom<Bytes>,
    <T as TryFrom<Bytes>>::Error: Into<BoxError>,
    Buf: Into<Bytes>,
    I: Iterator<Item = Buf> + Send,
{
    fn from(value: I) -> Self {
        LengthDelimitedStream::new(iter(value).map(|buf| Ok(buf.into())))
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod test {
    use super::*;

    mod unit_test {
        use super::*;
        use crate::{
            ff::{Fp31, Fp32BitPrime, Serializable},
            secret_sharing::replicated::semi_honest::AdditiveShare,
        };
        use futures_util::{StreamExt, TryStreamExt};
        use generic_array::GenericArray;

        #[tokio::test]
        async fn records_stream_fp31() {
            let vec = vec![3; 10];
            let stream = RecordsStream::from(vec.clone());
            let collected = stream.try_collect::<Vec<Vec<Fp31>>>().await.unwrap();

            // since `from_slice` chunks by the entire slice, expect the entire slice in `collected`
            assert_eq!(collected.len(), 1);
            assert_eq!(collected[0], vec![Fp31::try_from(3).unwrap(); 10]);
        }

        #[tokio::test]
        async fn records_stream_fp32_bit_prime() {
            const ARR_SIZE: usize = 50;
            let vec = vec![7; ARR_SIZE * <Fp32BitPrime as Serializable>::Size::USIZE];
            let stream = RecordsStream::from(vec.clone());
            let collected = stream
                .try_collect::<Vec<Vec<Fp32BitPrime>>>()
                .await
                .unwrap();

            // since `from_slice` chunks by the entire slice, expect the entire slice in `collected`
            assert_eq!(collected.len(), 1);
            assert_eq!(
                collected[0],
                vec![Fp32BitPrime::try_from(0x0707_0707).unwrap(); ARR_SIZE]
            );
        }

        #[tokio::test]
        async fn records_stream_fails_on_invalid_size() {
            const ARR_SIZE: usize = 5;
            // 1 extra byte
            let vec = vec![4u8; ARR_SIZE * <Fp32BitPrime as Serializable>::Size::USIZE + 1];
            let mut stream = RecordsStream::from(vec.clone());
            // valid values
            let n: Vec<Fp32BitPrime> = stream.next().await.unwrap().unwrap();
            assert_eq!(n, vec![0x0404_0404; ARR_SIZE]);

            // invalid remainder
            let err = stream.next().await.unwrap().unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::WriteZero);
        }

        // this test confirms that `RecordsStream` doesn't buffer more than it needs to as it produces
        // bytes
        #[tokio::test]
        async fn records_stream_buffers_optimally() {
            const ARR_SIZE: usize = 20;
            const CHUNK_SIZE: usize = 3;
            let vec = vec![7u8; ARR_SIZE * <Fp32BitPrime as Serializable>::Size::USIZE];
            let chunks = vec
                .chunks(CHUNK_SIZE)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            let mut stream = RecordsStream::<Fp32BitPrime, _>::from(chunks);
            assert_eq!(stream.buffer.len(), 0);
            for expected_chunk in vec.chunks(<Fp32BitPrime as Serializable>::Size::USIZE) {
                let expected =
                    Fp32BitPrime::deserialize(<&GenericArray<u8, _>>::from(expected_chunk));
                let n = stream.next().await.unwrap().unwrap();
                // `RecordsStream` outputs correct value
                assert_eq!(vec![expected], n);
                // `RecordsStream` only contains at most 1 buffered chunk
                assert!(stream.buffer.buffered.len() <= 1);
                // `RecordsStream` only contains at most `CHUNK_SIZE` values in its buffer
                assert!(stream.buffer.buffered_size <= CHUNK_SIZE);
            }
        }

        // checks that the `RecordsStream` will return chunks that are multiples of `SIZE_IN_BYTES`
        #[tokio::test]
        async fn returns_multiples() {
            const ARR_SIZE: usize = 201;
            const SIZE_IN_BYTES: usize = <Fp32BitPrime as Serializable>::Size::USIZE;
            const CHUNK_SIZE: usize = 4;
            let vec = vec![8u8; ARR_SIZE * SIZE_IN_BYTES];
            let chunks = vec
                .chunks(CHUNK_SIZE * SIZE_IN_BYTES)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            let mut stream = RecordsStream::<Fp32BitPrime, _>::from(chunks);
            let mut seen_count = 0;
            loop {
                let next_chunk = stream.next().await.unwrap().unwrap();
                let chunk_len = next_chunk.len();
                if chunk_len != CHUNK_SIZE {
                    assert_eq!(chunk_len, ARR_SIZE - seen_count);
                    break;
                }
                seen_count += chunk_len;
            }
            assert!(stream.next().await.is_none());
        }

        // checks that `RecordsStream` can handles unaligned chunk sizes
        #[tokio::test]
        async fn returns_multiples_unaligned() {
            const ARR_SIZE: usize = 200;
            const SIZE_IN_BYTES: usize = <AdditiveShare<Fp32BitPrime> as Serializable>::Size::USIZE;
            const CHUNK_SIZE: usize = SIZE_IN_BYTES * 5 + 7;
            let vec = vec![9u8; ARR_SIZE * SIZE_IN_BYTES];
            let chunks = vec
                .chunks(CHUNK_SIZE)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            let mut stream = RecordsStream::<AdditiveShare<Fp32BitPrime>, _>::from(chunks);

            let mut seen_count = 0;
            let mut more_than_one = false;
            while let Some(Ok(items)) = stream.next().await {
                if items.len() > 1 {
                    more_than_one = true;
                }
                seen_count += items.len();
            }
            assert_eq!(seen_count, ARR_SIZE);
            assert!(more_than_one);
        }
    }

    mod prop_test {
        use crate::ff::Fp32BitPrime;

        use super::*;
        use futures::TryStreamExt;
        use generic_array::GenericArray;
        use proptest::prelude::*;
        use rand::{rngs::StdRng, SeedableRng};

        prop_compose! {
            fn arb_size_in_bytes(field_size: usize, max_multiplier: usize)
                                (multiplier in 1..max_multiplier)
            -> usize {
                field_size * multiplier
            }
        }

        prop_compose! {
            fn arb_aligned_bytes(size_in_bytes: usize, max_len: usize)
                                (size_in_bytes in Just(size_in_bytes), len in 1..(max_len))
                                (vec in prop::collection::vec(any::<u8>(), len * size_in_bytes))
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

        prop_compose! {
            fn arb_expected_and_chunked_body(max_multiplier: usize, max_len: usize)
                                            (size_in_bytes in arb_size_in_bytes(<Fp32BitPrime as Serializable>::Size::USIZE, max_multiplier), max_len in Just(max_len))
                                            (data in arb_aligned_bytes(size_in_bytes, max_len), seed in any::<u64>())
            -> (Vec<Fp32BitPrime>, Vec<Vec<u8>>, u64) {
                let expected = data.chunks(<Fp32BitPrime as Serializable>::Size::USIZE)
                    .map(|chunk| Fp32BitPrime::deserialize(<&GenericArray<u8, _>>::from(chunk)))
                    .collect();
                (expected, random_chunks(&data, &mut StdRng::seed_from_u64(seed)), seed)
            }
        }

        proptest::proptest! {
            #[test]
            fn test_records_stream_works_with_any_chunks(
                (expected_bytes, chunked_bytes, _seed) in arb_expected_and_chunked_body(30, 100)
            ) {
                tokio::runtime::Runtime::new().unwrap().block_on(async {
                    // flatten the chunks to compare with expected
                    let collected_bytes = RecordsStream::<Fp32BitPrime, _>::from(chunked_bytes)
                        .try_concat()
                        .await
                        .unwrap();

                    assert_eq!(collected_bytes, expected_bytes);
                });
            }
        }
    }
}
