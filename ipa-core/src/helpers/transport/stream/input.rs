use std::{
    cmp::max,
    collections::VecDeque,
    convert::Infallible,
    fmt::{Debug, Formatter},
    future::Ready,
    io,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{
    Stream, StreamExt,
    stream::{Fuse, FusedStream, Iter, Map, Once, iter, once},
};
use generic_array::GenericArray;
use pin_project::pin_project;
use typenum::{U2, Unsigned};

use crate::{error::BoxError, ff::Serializable, helpers::BytesStream};

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
    #[cfg(all(test, unit_test))]
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
    fn read_multi<T: Serializable>(
        &mut self,
        count: usize,
    ) -> Option<Result<Vec<T>, T::DeserializationError>> {
        self.read_bytes(count * T::Size::USIZE).map(|bytes| {
            bytes
                .chunks(T::Size::USIZE)
                .map(|bytes| T::deserialize(GenericArray::from_slice(bytes)))
                .collect::<Result<_, _>>()
        })
    }

    /// Deserialize a single instance of `T` from the buffer with the guarantee that deserialization
    /// cannot fail, if there is enough bytes in the buffer.
    ///
    /// Returns `None` if there is insufficient data available.
    fn read_infallible<T: Serializable<DeserializationError = Infallible>>(&mut self) -> Option<T> {
        self.read_bytes(T::Size::USIZE)
            .map(|bytes| T::deserialize_infallible(GenericArray::from_slice(&bytes)))
    }
    /// Attempts to deserialize a single instance of `T` from the buffer.
    ///
    /// Returns `None` if there is insufficient data available, and an error if deserialization fails.
    fn try_read<T: Serializable>(&mut self) -> Option<Result<T, T::DeserializationError>> {
        self.read_bytes(T::Size::USIZE)
            .map(|bytes| T::deserialize(GenericArray::from_slice(&bytes)))
    }

    /// Update the buffer with the result of polling a stream.
    fn extend(&mut self, bytes: Option<Result<Bytes, BoxError>>) -> ExtendResult {
        match bytes {
            // if body is expended, but we have some bytes leftover, error due to misaligned
            // output
            None if self.buffered_size > 0 => ExtendResult::Error(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("stream terminated with {} extra bytes", self.buffered_size),
            )),

            // if body is finished with no more bytes remaining, this stream is finished.
            // equivalent of `None if self.buffered_size == 0 =>`
            None => ExtendResult::Finished,

            // if body produces error, forward the error
            Some(Err(err)) => {
                ExtendResult::Error(io::Error::new(io::ErrorKind::UnexpectedEof, err))
            }

            // if body has more bytes, push it into the buffer
            Some(Ok(bytes)) => {
                self.buffered_size += bytes.len();
                self.buffered.push_back(bytes);
                ExtendResult::Ok
            }
        }
    }
}

enum ExtendResult {
    /// Data from the stream was appended to the buffer.
    Ok,
    /// The stream finished cleanly.
    Finished,
    /// The stream errored.
    Error(io::Error),
}

pub trait Mode {
    type Output<T: Serializable>;

    fn read_from<T: Serializable>(
        buf: &mut BufDeque,
    ) -> Option<Result<Self::Output<T>, T::DeserializationError>>;
}

/// Makes [`RecordsStream`] return one record per poll.
pub struct Single;

/// Makes [`RecordsStream`] return a vector of elements per poll.
pub struct Batch;

impl Mode for Single {
    type Output<T: Serializable> = T;

    fn read_from<T: Serializable>(
        buf: &mut BufDeque,
    ) -> Option<Result<Self::Output<T>, T::DeserializationError>> {
        buf.try_read()
    }
}
impl Mode for Batch {
    type Output<T: Serializable> = Vec<T>;

    fn read_from<T: Serializable>(
        buf: &mut BufDeque,
    ) -> Option<Result<Self::Output<T>, T::DeserializationError>> {
        let count = max(1, buf.contiguous_len() / T::Size::USIZE);
        buf.read_multi(count)
    }
}

/// Parse a [`Stream`] of bytes into a stream of records of some
/// fixed-length-[`Serializable`] type `T`.
///
/// Depending on `M`, the provided stream can yield a single record `T` or multiples of `T`. See
/// [`Single`], [`Batch`] and [`Mode`]
#[pin_project]
pub struct RecordsStream<T, S, M = Batch>
where
    S: BytesStream,
    T: Serializable,
    M: Mode,
{
    // Our implementation of `poll_next` turns a `None` from the inner stream into `Some(Err(_))` if
    // there is extra trailing data. We do not expect to be polled again after that happens, but
    // doing so is allowed by the `Stream` trait, so we need a fuse to ensure we don't poll the
    // inner stream after it finishes.
    #[pin]
    stream: Fuse<S>,
    buffer: BufDeque,
    phantom_data: PhantomData<(T, M)>,
}

pub type SingleRecordStream<T, S> = RecordsStream<T, S, Single>;

impl<T, S, M> RecordsStream<T, S, M>
where
    S: BytesStream,
    T: Serializable,
    M: Mode,
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

impl<T, S, M> Stream for RecordsStream<T, S, M>
where
    S: BytesStream,
    T: Serializable,
    M: Mode,
{
    type Item = Result<M::Output<T>, crate::error::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        loop {
            if let Some(v) = M::read_from(this.buffer) {
                return Poll::Ready(Some(v.map_err(|e: T::DeserializationError| {
                    crate::error::Error::ParseError(e.into())
                })));
            }

            // We need more data, poll the stream
            let Poll::Ready(polled_item) = this.stream.as_mut().poll_next(cx) else {
                return Poll::Pending;
            };

            match this.buffer.extend(polled_item) {
                ExtendResult::Finished => return Poll::Ready(None),
                ExtendResult::Error(err) => return Poll::Ready(Some(Err(err.into()))),
                ExtendResult::Ok => (),
            }
        }
    }
}

impl<T, S, M> FusedStream for RecordsStream<T, S, M>
where
    S: BytesStream,
    T: Serializable,
    M: Mode,
{
    fn is_terminated(&self) -> bool {
        self.stream.is_terminated()
    }
}

impl<T, S, M> Debug for RecordsStream<T, S, M>
where
    S: BytesStream,
    T: Serializable,
    M: Mode,
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

impl<T, Buf, I, M> From<I>
    for RecordsStream<T, Map<Iter<I::IntoIter>, fn(Buf) -> Result<Bytes, BoxError>>, M>
where
    T: Serializable,
    Buf: Into<Bytes>,
    I: IntoIterator<Item = Buf>,
    <I as IntoIterator>::IntoIter: Send,
    M: Mode,
{
    fn from(value: I) -> Self {
        RecordsStream::new(iter(value).map(|buf| Ok(buf.into())))
    }
}

struct Length(u16);

impl Serializable for Length {
    type Size = U2;
    type DeserializationError = Infallible;

    fn serialize(&self, buf: &mut generic_array::GenericArray<u8, Self::Size>) {
        *buf.as_mut() = self.0.to_le_bytes();
    }

    fn deserialize(
        buf: &generic_array::GenericArray<u8, Self::Size>,
    ) -> Result<Self, Self::DeserializationError> {
        Ok(Self(u16::from_le_bytes(<[u8; 2]>::from(*buf))))
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
        let mut available_len = 0;
        let mut consumed_len = 0;
        let mut items = Vec::new();
        loop {
            if this.pending_len.is_none() {
                if let Some(len) = this.buffer.read_infallible::<Length>().map(Into::into) {
                    *this.pending_len = Some(len);
                    consumed_len += <Length as Serializable>::Size::USIZE;
                }
            }

            if let Some(len) = *this.pending_len {
                let bytes = if len == 0 {
                    Some(Bytes::from(&[] as &[u8]))
                } else {
                    this.buffer.read_bytes(len)
                };
                if let Some(bytes) = bytes {
                    *this.pending_len = None;
                    consumed_len += len;
                    match T::try_from(bytes) {
                        Ok(item) => {
                            items.push(item);
                            if available_len != 0 && consumed_len < available_len {
                                continue;
                            }
                        }
                        // TODO: Since we need to recover from individual invalid reports, we
                        // probably need `type Item = Result<Vec<Result<T, ?>>, io::Error>`, and we
                        // need to flush (rather than discard) pending `items` from before the
                        // error.
                        Err(err) => {
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                err,
                            ))));
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

            match this.buffer.extend(polled_item) {
                ExtendResult::Finished if this.pending_len.is_some() => {
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        format!(
                            "stream terminated with {} extra bytes",
                            <Length as Serializable>::Size::USIZE
                        ),
                    ))));
                }
                ExtendResult::Finished => return Poll::Ready(None),
                ExtendResult::Error(err) => return Poll::Ready(Some(Err(err))),
                ExtendResult::Ok if available_len == 0 => {
                    available_len = this.buffer.contiguous_len();
                    items.reserve(1 + available_len / ESTIMATED_AVERAGE_REPORT_SIZE);
                }
                ExtendResult::Ok => (),
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

#[cfg(all(test, unit_test))]
mod test {
    use rand::Rng;
    use rand_core::RngCore;

    use super::*;

    mod unit_test {
        use std::io;

        use futures::{StreamExt, TryStreamExt};
        use generic_array::GenericArray;
        use typenum::Unsigned;

        use crate::{
            error::Error,
            ff::{Fp31, Fp32BitPrime, Serializable},
            helpers::RecordsStream,
            secret_sharing::replicated::semi_honest::AdditiveShare,
        };

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
            if let Error::Io(err) = err {
                assert_eq!(err.kind(), io::ErrorKind::WriteZero);
            } else {
                panic!("unexpected error: {err}")
            }
        }

        // this test confirms that `RecordsStream` doesn't buffer more than it needs to as it produces
        // bytes
        #[tokio::test]
        async fn records_stream_buffers_optimally() {
            const ARR_SIZE: usize = 20;
            const CHUNK_SIZE: usize = 3;
            let vec = [7u8; ARR_SIZE * <Fp32BitPrime as Serializable>::Size::USIZE];
            let chunks = vec
                .chunks(CHUNK_SIZE)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            let mut stream = RecordsStream::<Fp32BitPrime, _>::from(chunks);
            assert_eq!(stream.buffer.len(), 0);
            for expected_chunk in vec.chunks(<Fp32BitPrime as Serializable>::Size::USIZE) {
                let expected =
                    Fp32BitPrime::deserialize_unchecked(GenericArray::from_slice(expected_chunk));
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

    mod single_record {
        use std::iter;

        use bytes::Bytes;
        use futures_util::{FutureExt, StreamExt, TryStreamExt};

        use crate::{
            ff::{Fp31, Fp32BitPrime},
            helpers::{RecordsStream, transport::stream::input::Single},
            secret_sharing::SharedValue,
        };

        #[tokio::test]
        async fn fp31() {
            let vec = vec![3; 10];
            let stream = RecordsStream::<Fp31, _, Single>::from(iter::once(Bytes::from(vec)));
            let collected = stream.try_collect::<Vec<Fp31>>().await.unwrap();

            assert_eq!(collected, vec![Fp31::try_from(3).unwrap(); 10]);
        }

        #[tokio::test]
        #[should_panic(expected = "stream terminated with 3 extra bytes")]
        async fn fp32_bit() {
            let vec = vec![0; 7];
            let mut stream =
                RecordsStream::<Fp32BitPrime, _, Single>::from(iter::once(Bytes::from(vec)));
            assert_eq!(
                Fp32BitPrime::ZERO,
                stream.next().now_or_never().flatten().unwrap().unwrap()
            );
            stream.next().now_or_never().flatten().unwrap().unwrap();
        }
    }

    mod delimited {
        use futures::TryStreamExt;

        use super::*;

        #[tokio::test]
        async fn basic() {
            let input = vec![
                Ok(Bytes::from(vec![2, 0, 0x11, 0x22, 3, 0, 0x33, 0x44, 0x55])),
                Ok(Bytes::from(vec![
                    1, 0, 0x66, 0, 0, 4, 0, 0x77, 0x88, 0x99, 0xaa,
                ])),
            ];
            let stream = LengthDelimitedStream::<Bytes, _>::new(iter(input));
            let output = stream.try_collect::<Vec<Vec<Bytes>>>().await.unwrap();

            assert_eq!(output.len(), 2);
            assert_eq!(output[0].len(), 2);
            assert_eq!(output[1].len(), 3);
            assert_eq!(output[0][0], vec![0x11, 0x22]);
            assert_eq!(output[0][1], vec![0x33, 0x44, 0x55]);
            assert_eq!(output[1][0], vec![0x66]);
            assert_eq!(output[1][1], vec![]);
            assert_eq!(output[1][2], vec![0x77, 0x88, 0x99, 0xaa]);
        }

        #[tokio::test]
        async fn fragmented() {
            let input = vec![
                2, 0, 0x11, 0x22, 3, 0, 0x33, 0x44, 0x55, 1, 0, 0x66, 4, 0, 0x77, 0x88, 0x99, 0xaa,
            ]
            .into_iter()
            .map(|byte| Ok(Bytes::from(vec![byte])));
            let stream = LengthDelimitedStream::<Bytes, _>::new(iter(input));
            let output = stream.try_collect::<Vec<Vec<Bytes>>>().await.unwrap();

            assert_eq!(output.len(), 4);
            assert_eq!(output[0][0], vec![0x11, 0x22]);
            assert_eq!(output[1][0], vec![0x33, 0x44, 0x55]);
            assert_eq!(output[2][0], vec![0x66]);
            assert_eq!(output[3][0], vec![0x77, 0x88, 0x99, 0xaa]);
        }

        #[tokio::test]
        async fn incomplete_length() {
            let input = vec![Ok(Bytes::from(vec![2, 0, 0x11, 0x22, 3]))];
            let stream = LengthDelimitedStream::<Bytes, _>::new(iter(input));
            let err = stream.try_collect::<Vec<Vec<Bytes>>>().await.unwrap_err();

            assert_eq!(err.kind(), io::ErrorKind::WriteZero);
        }

        #[tokio::test]
        async fn complete_length_no_data() {
            let input = vec![Ok(Bytes::from(vec![2, 0, 0x11, 0x22, 3, 0]))];
            let stream = LengthDelimitedStream::<Bytes, _>::new(iter(input));
            let err = stream.try_collect::<Vec<Vec<Bytes>>>().await.unwrap_err();

            assert_eq!(err.kind(), io::ErrorKind::WriteZero);
        }

        #[tokio::test]
        async fn incomplete_data() {
            let input = vec![Ok(Bytes::from(vec![2, 0, 0x11, 0x22, 3, 0, 0x33]))];
            let stream = LengthDelimitedStream::<Bytes, _>::new(iter(input));
            let err = stream.try_collect::<Vec<Vec<Bytes>>>().await.unwrap_err();

            assert_eq!(err.kind(), io::ErrorKind::WriteZero);
        }
    }

    // Helper for prop tests
    fn random_chunks<R: RngCore>(mut slice: &[u8], rng: &mut R) -> Vec<Vec<u8>> {
        let mut output = Vec::new();
        if slice.is_empty() {
            return output;
        }
        loop {
            let len = slice.len();
            let idx = rng.gen_range(1..=len);
            match idx {
                split_idx if split_idx == len => {
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

    mod prop_test {
        use futures::TryStreamExt;
        use proptest::prelude::*;
        use rand::{SeedableRng, rngs::StdRng};

        use super::*;

        type TestField = crate::ff::Fp32BitPrime;

        prop_compose! {
            fn arb_expected_and_chunked_body(max_len: usize)
                                            (len in 0..=max_len)
                                            (expected in prop::collection::vec(any::<TestField>(), len), seed in any::<u64>())
            -> (Vec<TestField>, Vec<Vec<u8>>, u64) {
                let mut bytes = Vec::with_capacity(expected.len() * <TestField as Serializable>::Size::USIZE);
                for val in &expected {
                    let mut buf = [0u8; <TestField as Serializable>::Size::USIZE].into();
                    val.serialize(&mut buf);
                    bytes.extend(buf.as_slice());
                }
                (expected, random_chunks(&bytes, &mut StdRng::seed_from_u64(seed)), seed)
            }
        }

        proptest::proptest! {
            #[test]
            fn batch_test_records_stream_works_with_any_chunks(
                (expected_bytes, chunked_bytes, _seed) in arb_expected_and_chunked_body(100)
            ) {
                tokio::runtime::Runtime::new().unwrap().block_on(async {
                    // flatten the chunks to compare with expected
                    let collected_bytes = RecordsStream::<TestField, _>::from(chunked_bytes)
                        .try_concat()
                        .await
                        .unwrap();

                    assert_eq!(collected_bytes, expected_bytes);
                });
            }

            #[test]
            fn single_test_records_stream_works_with_any_chunks(
                (expected_bytes, chunked_bytes, _seed) in arb_expected_and_chunked_body(100)
            ) {
                tokio::runtime::Runtime::new().unwrap().block_on(async {
                    let collected_bytes = RecordsStream::<TestField, _, Single>::from(chunked_bytes)
                        .try_collect::<Vec<_>>()
                        .await
                        .unwrap();

                    assert_eq!(collected_bytes, expected_bytes);
                });
            }
        }
    }

    mod delimited_prop_test {
        use std::{mem::size_of, ops::Range};

        use bytes::BufMut;
        use futures::TryStreamExt;
        use proptest::prelude::*;
        use rand::{SeedableRng, rngs::StdRng};

        use super::*;

        #[derive(Copy, Clone, Debug)]
        enum ItemSize {
            Small,
            Normal,
            Large,
            Huge,
            SmallRandom,
            FullRandom,
        }

        fn item_size_strategy(with_large: bool) -> BoxedStrategy<ItemSize> {
            if with_large {
                prop_oneof![
                    10 => Just(ItemSize::Small),
                    70 => Just(ItemSize::Normal),
                    10 => Just(ItemSize::Large),
                    5 => Just(ItemSize::Huge),
                    5 => Just(ItemSize::FullRandom),
                ]
                .boxed()
            } else {
                prop_oneof![
                    10 => Just(ItemSize::Small),
                    70 => Just(ItemSize::Normal),
                    20 => Just(ItemSize::SmallRandom),
                ]
                .boxed()
            }
        }

        fn item_size(size: ItemSize) -> Range<usize> {
            match size {
                ItemSize::Small => 0..32,
                ItemSize::Normal => 60..120,
                ItemSize::Large => 500..2000,
                ItemSize::Huge => 40000..u16::MAX as usize,
                ItemSize::FullRandom => 0..u16::MAX as usize,
                ItemSize::SmallRandom => 0..1000,
            }
        }

        prop_compose! {
            fn random_item(with_large: bool)
                          (size in item_size_strategy(with_large))
                          (vec in prop::collection::vec(any::<u8>(), item_size(size)))
            -> Vec<u8> {
                vec
            }
        }

        prop_compose! {
            fn random_items(max_len: usize, with_large: bool)
                           (len in 0..=max_len)
                           (items in prop::collection::vec(random_item(with_large), len))
            -> Vec<Vec<u8>> {
                items
            }
        }

        fn flatten_delimited(items: &[Vec<u8>]) -> Vec<u8> {
            let total_len =
                items.len() * size_of::<u16>() + items.iter().fold(0, |acc, item| acc + item.len());
            let mut output = Vec::with_capacity(total_len);
            for item in items {
                output.put_u16_le(item.len().try_into().unwrap());
                output.put_slice(item.as_slice());
            }
            output
        }

        prop_compose! {
            fn arb_expected_and_chunked_body(max_len: usize)
                                            (with_large in prop::bool::weighted(0.05))
                                            (items in random_items(max_len, with_large), seed in any::<u64>())
            -> (Vec<Vec<u8>>, Vec<Vec<u8>>, u64) {
                let flattened = flatten_delimited(items.as_slice());
                (items, random_chunks(&flattened, &mut StdRng::seed_from_u64(seed)), seed)
            }
        }

        proptest::proptest! {
            #[test]
            fn test_delimited_stream_works_with_any_chunks(
                (expected_items, chunked_bytes, _seed) in arb_expected_and_chunked_body(100)
            ) {
                tokio::runtime::Runtime::new().unwrap().block_on(async {
                    let input = iter(chunked_bytes.into_iter().map(|vec| Ok(Bytes::from(vec))));
                    // flatten the chunks to compare with expected
                    let collected_items = LengthDelimitedStream::<Bytes, _>::new(input)
                        .try_concat()
                        .await
                        .unwrap();

                    assert_eq!(collected_items, expected_items);
                });
            }
        }
    }
}
