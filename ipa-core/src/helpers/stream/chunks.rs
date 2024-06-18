use std::{
    fmt::Display,
    future::Future,
    iter::Take,
    mem,
    ops::{Deref, RangeInclusive},
    pin::Pin,
    task::{ready, Context, Poll},
};

use futures::{stream::FusedStream, Stream, TryStream};
use pin_project::pin_project;
use typenum::{Const, ToUInt, Unsigned};

use crate::{
    error::{Error, LengthError},
    helpers::MaybeFuture,
};

/// A chunk of `N` records that may be borrowed or owned.
///
/// This type is used for the input data to processing functions.
#[derive(Clone, Debug)]
pub enum ChunkData<'a, T, const N: usize> {
    Borrowed(&'a [T; N]),
    Owned(Box<[T; N]>),
}

impl<'a, T, const N: usize> Deref for ChunkData<'a, T, N> {
    type Target = [T; N];

    fn deref(&self) -> &Self::Target {
        match *self {
            ChunkData::Borrowed(r) => r,
            ChunkData::Owned(ref v) => v.as_ref(),
        }
    }
}

/// Tracks whether a chunk is full or partial.
///
/// If the record count is not a multiple of the chunk size, the last chunk will be a partial chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkType {
    Full,
    Partial(usize),
}

/// An owned chunk that may be fully or partially valid.
///
/// This type is used for the output data from processing functions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Chunk<K, const N: usize> {
    chunk_type: ChunkType,
    data: K,
}

impl<K, const N: usize> Chunk<K, N> {
    /// Apply a transformation to the chunk data
    pub fn map<F, KM>(self, f: F) -> Chunk<KM, N>
    where
        F: FnOnce(K) -> KM,
    {
        let Self { chunk_type, data } = self;

        Chunk {
            chunk_type,
            data: f(data),
        }
    }

    /// Apply a transformation to the chunk data via a `Future`
    pub fn then<F, Fut, KM>(self, f: F) -> ChunkFuture<Fut, KM, N>
    where
        F: FnOnce(K) -> Fut,
        Fut: Future<Output = Result<KM, Error>>,
    {
        let Self { chunk_type, data } = self;

        ChunkFuture::new(f(data), chunk_type)
    }
}

enum Expected {
    /// For the final, partial chunk, we require at least as many sub-chunks as necessary to hold
    /// the specified amount of data, and at most a full chunk. It is probably only reasonable to
    /// get one or the other, and not something in between, but we allow that for now.
    Range(RangeInclusive<usize>),
    Exactly(usize),
}

impl Display for Expected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expected::Range(bounds) => write!(
                f,
                "between {min} and {max}",
                min = bounds.start(),
                max = bounds.end()
            ),
            Expected::Exactly(value) => value.fmt(f),
        }
    }
}

impl Expected {
    fn type_str(&self) -> &'static str {
        match self {
            Expected::Range(_) => "partial",
            Expected::Exactly(_) => "full",
        }
    }

    fn contains(&self, value: usize) -> bool {
        match *self {
            Expected::Range(ref exp_range) => exp_range.contains(&value),
            Expected::Exactly(exp_value) => exp_value == value,
        }
    }
}

impl<T, const N: usize> Chunk<Vec<T>, N> {
    /// Unpack nested chunks
    ///
    /// This function can be used when converting between vectorization factors. Before calling this function,
    /// the protocol code needs to convert (e.g. using `Chunk::map` or `Chunk::then`) the chunk data into a
    /// vector of N / M sub-chunks with data type `T`. This function will then convert the `Chunk<Vec<T>, N>`
    /// into a vector with type `Vec<Chunk<T, M>>` containing up to N / M chunks. Note that the result may
    /// be shorter than N / M chunks, if the input was a partial chunk.
    ///
    /// # Panics
    /// If the data stream is not valid for the specified chunk and sub-chunk configuration.
    #[must_use]
    pub fn unpack<const M: usize>(self) -> Vec<Chunk<T, M>> {
        let Self { chunk_type, data } = self;
        debug_assert!(N % M == 0);
        let (mut len, expected) = if let ChunkType::Partial(len) = chunk_type {
            (len, Expected::Range(((len + M - 1) / M)..=(N / M)))
        } else {
            (N, Expected::Exactly(N / M))
        };
        assert!(
            expected.contains(data.len()),
            "input to Chunk::unpack (N = {N}, M = {M}) was not chunked properly. \
             {type_str} input chunk should contain {expected} sub-chunks, found {len}",
            type_str = expected.type_str(),
            len = data.len(),
        );
        data.into_iter()
            .map_while(|item| {
                if len == 0 {
                    None
                } else if len >= M {
                    len -= M;
                    Some(Chunk {
                        chunk_type: ChunkType::Full,
                        data: item,
                    })
                } else {
                    Some(Chunk {
                        chunk_type: ChunkType::Partial(mem::replace(&mut len, 0)),
                        data: item,
                    })
                }
            })
            .collect()
    }
}

impl<K: IntoIterator, const N: usize> IntoIterator for Chunk<K, N> {
    type Item = K::Item;
    type IntoIter = Take<K::IntoIter>;

    fn into_iter(self) -> Self::IntoIter {
        let len = match self.chunk_type {
            ChunkType::Full => N,
            ChunkType::Partial(len) => len,
        };
        self.data.into_iter().take(len)
    }
}

/// Future for a chunk of processed data.
#[pin_project]
pub struct ChunkFuture<Fut, K, const N: usize>
where
    Fut: Future<Output = Result<K, Error>>,
{
    #[pin]
    fut: Fut,
    chunk_type: ChunkType,
}

pub type MaybeChunkFuture<Fut, K, const N: usize> = MaybeFuture<ChunkFuture<Fut, K, N>>;

impl<Fut, K, const N: usize> ChunkFuture<Fut, K, N>
where
    Fut: Future<Output = Result<K, Error>>,
{
    fn new(fut: Fut, chunk_type: ChunkType) -> Self {
        Self { fut, chunk_type }
    }
}

impl<Fut, K, const N: usize> Future for ChunkFuture<Fut, K, N>
where
    Fut: Future<Output = Result<K, Error>>,
{
    type Output = Result<Chunk<K, N>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.fut.poll(cx) {
            Poll::Ready(Ok(data)) => Poll::Ready(Ok(Chunk {
                chunk_type: *this.chunk_type,
                data,
            })),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Stream returned by `process_slice_by_chunks`.
//
// We could avoid pin projection and instead require that `SliceChunkProcessor` (and its fields) be
// `Unpin`.  Requiring `D: Unpin` is easy, but requiring `F: Unpin` in turn requires a bunch of `C:
// Unpin` bounds in protocols.
#[pin_project]
struct SliceChunkProcessor<'a, T, K, F, Fut, D, const N: usize>
where
    T: Clone + 'a,
    F: Fn(usize, ChunkData<'a, T, N>) -> Fut,
    Fut: Future<Output = Result<K, Error>> + 'a,
    D: Fn() -> T,
{
    slice: &'a [T],

    /// Current input position, counted in chunks.
    pos: usize,

    /// Number of records in the final partial chunk.
    ///
    /// Cleared to zero after the partial chunk is processed.
    remainder_len: usize,

    process_fn: F,

    pad_record_fn: D,
}

impl<'a, T, K, F, Fut, D, const N: usize> SliceChunkProcessor<'a, T, K, F, Fut, D, N>
where
    T: Clone,
    F: Fn(usize, ChunkData<'a, T, N>) -> Fut,
    Fut: Future<Output = Result<K, Error>> + 'a,
    D: Fn() -> T,
{
    fn next_chunk(self: Pin<&mut Self>) -> Option<ChunkFuture<Fut, K, N>> {
        let this = self.project();

        let whole_chunks = this.slice.len() / N;

        if *this.pos < whole_chunks {
            let idx = *this.pos;
            let slice = &this.slice[N * idx..N * (idx + 1)];
            *this.pos += 1;
            Some(ChunkFuture::new(
                (*this.process_fn)(idx, ChunkData::Borrowed(slice.try_into().unwrap())),
                ChunkType::Full,
            ))
        } else if *this.pos == whole_chunks && *this.remainder_len != 0 {
            let idx = *this.pos;
            let remainder_len = mem::replace(this.remainder_len, 0);
            let mut last_chunk = Vec::with_capacity(N);
            last_chunk.extend_from_slice(&this.slice[N * idx..]);
            last_chunk.resize_with(N, this.pad_record_fn);
            let last_chunk = Box::<[T; N]>::try_from(last_chunk).ok().unwrap();
            Some(ChunkFuture::new(
                (*this.process_fn)(idx, ChunkData::Owned(last_chunk)),
                ChunkType::Partial(remainder_len),
            ))
        } else {
            return None;
        }
    }
}

impl<'a, T, K, F, Fut, D, const N: usize> Stream for SliceChunkProcessor<'a, T, K, F, Fut, D, N>
where
    T: Clone,
    F: Fn(usize, ChunkData<'a, T, N>) -> Fut,
    Fut: Future<Output = Result<K, Error>> + 'a,
    D: Fn() -> T,
{
    type Item = ChunkFuture<Fut, K, N>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.next_chunk())
    }
}

pub fn process_slice_by_chunks<'a, T, K, F, Fut, D, const N: usize>(
    slice: &'a [T],
    process_fn: F,
    pad_record_fn: D,
) -> impl Stream<Item = ChunkFuture<Fut, K, N>> + 'a
where
    T: Clone,
    K: 'a,
    F: Fn(usize, ChunkData<'a, T, N>) -> Fut + 'a,
    Fut: Future<Output = Result<K, Error>> + 'a,
    D: Fn() -> T + 'a,
{
    SliceChunkProcessor {
        slice,
        pos: 0,
        remainder_len: slice.len() % N,
        process_fn,
        pad_record_fn,
    }
}

pub trait ChunkBuffer<const N: usize> {
    type Item;
    type Chunk;

    fn push(&mut self, item: Self::Item);
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn resize_with<F: Fn() -> Self::Item>(&mut self, len: usize, f: F);

    /// Return the collected chunk and clear the buffer.
    ///
    /// # Errors
    /// If the buffer does not have the correct length.
    fn take(&mut self) -> Result<Self::Chunk, LengthError>;
}

impl<const N: usize, T> ChunkBuffer<N> for Vec<T> {
    type Item = T;
    type Chunk = Box<[T; N]>;

    fn push(&mut self, item: T) {
        Vec::push(self, item);
    }

    fn len(&self) -> usize {
        Vec::len(self)
    }

    fn resize_with<F: Fn() -> Self::Item>(&mut self, len: usize, f: F) {
        Vec::resize_with(self, len, f);
    }

    fn take(&mut self) -> Result<Self::Chunk, LengthError> {
        match mem::replace(self, Vec::with_capacity(N)).try_into() {
            Ok(boxed) => Ok(boxed),
            Err(vec) => {
                *self = vec;
                Err(LengthError {
                    expected: N,
                    actual: self.len(),
                })
            }
        }
    }
}

/// Stream returned by `process_stream_by_chunks`.
#[pin_project]
struct StreamChunkProcessor<St, T, B, K, F, Fut, D, const N: usize>
where
    St: Stream<Item = Result<T, Error>> + Send,
    B: ChunkBuffer<N>,
    F: Fn(usize, B::Chunk) -> Fut,
    Fut: Future<Output = Result<K, Error>>,
    D: Fn() -> T,
{
    #[pin]
    stream: St,
    buffer: B,
    process_fn: F,
    pad_record_fn: Option<D>,

    /// Current input position, counted in chunks.
    pos: usize,
}

/// An `Option` verified to be `Some`, with an infallible `take()`.
struct DefinitelySome<'a, T>(&'a mut Option<T>);

impl<'a, T> TryFrom<&'a mut Option<T>> for DefinitelySome<'a, T> {
    type Error = ();

    fn try_from(value: &'a mut Option<T>) -> Result<Self, Self::Error> {
        match value {
            value @ Some(_) => Ok(DefinitelySome(value)),
            None => Err(()),
        }
    }
}

impl<'a, T> DefinitelySome<'a, T> {
    fn take(self) -> T {
        self.0.take().unwrap()
    }
}

impl<St, T, B, K, F, Fut, D, const N: usize> Stream
    for StreamChunkProcessor<St, T, B, K, F, Fut, D, N>
where
    St: Stream<Item = Result<T, Error>> + Send,
    B: ChunkBuffer<N, Item = T>,
    F: Fn(usize, B::Chunk) -> Fut,
    Fut: Future<Output = Result<K, Error>>,
    D: Fn() -> T,
{
    type Item = MaybeChunkFuture<Fut, K, N>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.as_mut().project();

        // pad_record_fn serves as our fuse -- it is taken out of the `Option` when we are finished.
        // In the case where we terminate early due to an error, fusing the inner stream cannot
        // serve this purpose.
        let Ok(pad_record_fn) = DefinitelySome::try_from(this.pad_record_fn) else {
            return Poll::Ready(None);
        };

        let (chunk_data, chunk_type) = loop {
            match ready!(this.stream.as_mut().poll_next(cx)) {
                Some(Ok(item)) => {
                    this.buffer.push(item);
                    if this.buffer.len() == N {
                        break (this.buffer.take(), ChunkType::Full);
                    }
                }
                Some(Err(e)) => {
                    pad_record_fn.take();
                    return Poll::Ready(Some(MaybeFuture::value(Err(e))));
                }
                None if this.buffer.len() != 0 => {
                    // Input stream ended, but we still have some items to process.
                    let remainder_len = this.buffer.len();
                    this.buffer.resize_with(N, pad_record_fn.take());
                    break (this.buffer.take(), ChunkType::Partial(remainder_len));
                }
                None => {
                    // Input stream ended at a chunk boundary. Unlike the partial chunk case, we
                    // return None, so we shouldn't be polled again regardless of pad_record_fn
                    // signalling, but might as well make this a fused stream since it's easy.
                    pad_record_fn.take();
                    return Poll::Ready(None);
                }
            }
        };
        let idx = *this.pos;
        *this.pos += 1;
        Poll::Ready(Some(MaybeFuture::future(ChunkFuture::new(
            (*this.process_fn)(idx, chunk_data.expect("ensured a full chunk")),
            chunk_type,
        ))))
    }
}

impl<St, T, B, K, F, Fut, D, const N: usize> FusedStream
    for StreamChunkProcessor<St, T, B, K, F, Fut, D, N>
where
    St: Stream<Item = Result<T, Error>> + Send,
    B: ChunkBuffer<N, Item = T>,
    F: Fn(usize, B::Chunk) -> Fut,
    Fut: Future<Output = Result<K, Error>>,
    D: Fn() -> T,
{
    fn is_terminated(&self) -> bool {
        self.pad_record_fn.is_none()
    }
}

/// Process stream through a function that operates on chunks.
///
/// Processes `stream` by collecting chunks of `N` items into `buffer`, then calling `process_fn`
/// for each chunk. If there is a partial chunk at the end of the stream, `pad_record_fn` is called
/// repeatedly to fill out the last chunk.
pub fn process_stream_by_chunks<St, T, B, K, F, Fut, D, const N: usize>(
    stream: St,
    buffer: B,
    process_fn: F,
    pad_record_fn: D,
) -> impl FusedStream<Item = MaybeChunkFuture<Fut, K, N>>
where
    St: Stream<Item = Result<T, Error>> + Send,
    B: ChunkBuffer<N, Item = T>,
    F: Fn(usize, B::Chunk) -> Fut,
    Fut: Future<Output = Result<K, Error>>,
    D: Fn() -> T,
{
    StreamChunkProcessor {
        stream,
        buffer,
        process_fn,
        pad_record_fn: Some(pad_record_fn),
        pos: 0,
    }
}

#[must_use]
#[allow(clippy::needless_pass_by_value)] // divisor argument is zero-size anyways
pub fn div_round_up<const DIVISOR: usize>(dividend: usize, _divisor: Const<DIVISOR>) -> usize
where
    Const<DIVISOR>: ToUInt,
    <Const<DIVISOR> as ToUInt>::Output: Unsigned + typenum::NonZero,
{
    let divisor = <Const<DIVISOR> as ToUInt>::Output::to_usize();
    (dividend + divisor - 1) / divisor
}

/// Trait to flatten a stream of iterables.
pub trait TryFlattenItersExt: TryStream {
    /// Flatten a `TryStream` of `IntoIterator`s.
    ///
    /// Similar to `TryStream::try_flatten`, but that flattens a `TryStream` of `TryStream`s.
    ///
    /// Also unlike `TryStream::try_flatten`, the `TryFlattenIters` stream ends the stream
    /// after the first error. This is particularly important when the error is security-
    /// related and may indicate future data is corrupt.
    fn try_flatten_iters<T, I>(self) -> impl Stream<Item = Result<T, Error>>
    where
        I: IntoIterator<Item = T>,
        Self: Stream<Item = Result<I, Error>> + Sized;
}

impl<St: TryStream> TryFlattenItersExt for St {
    fn try_flatten_iters<T, I>(self) -> impl Stream<Item = Result<T, Error>>
    where
        I: IntoIterator<Item = T>,
        Self: Stream<Item = Result<I, Error>> + Sized,
    {
        TryFlattenIters::new(self)
    }
}

/// Stream returned by `TryFlattenIters::try_flatten_iters`.
#[pin_project]
struct TryFlattenIters<T, I, St>
where
    I: IntoIterator<Item = T>,
    St: Stream<Item = Result<I, Error>>,
{
    #[pin]
    stream: St,
    iter: Option<<I as IntoIterator>::IntoIter>,
    finished: bool,
}

impl<T, I, St> TryFlattenIters<T, I, St>
where
    I: IntoIterator<Item = T>,
    St: Stream<Item = Result<I, Error>>,
{
    fn new(stream: St) -> Self {
        TryFlattenIters {
            stream,
            iter: None,
            finished: false,
        }
    }
}

impl<T, I, St> Stream for TryFlattenIters<T, I, St>
where
    I: IntoIterator<Item = T>,
    St: Stream<Item = Result<I, Error>>,
{
    type Item = Result<T, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.finished {
            return Poll::Ready(None);
        }

        let mut this = self.project();

        loop {
            if let Some(item) = this.iter.as_mut().and_then(Iterator::next) {
                return Poll::Ready(Some(Ok(item)));
            }
            *this.iter = None;
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(into_iter))) => *this.iter = Some(into_iter.into_iter()),
                Poll::Ready(Some(Err(e))) => {
                    // Terminate the stream after the first error.
                    *this.finished = true;
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(None) => {
                    *this.finished = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::{
        future::ready,
        iter::{self, FromFn},
        ops::Neg,
    };

    use futures::{
        channel::mpsc::channel,
        stream::{self, poll_immediate},
        SinkExt, StreamExt, TryStreamExt,
    };

    use super::*;

    impl<T, const N: usize> PartialEq<[T; N]> for Chunk<[T; N], N>
    where
        [T; N]: PartialEq<[T; N]>,
    {
        fn eq(&self, other: &[T; N]) -> bool {
            self.chunk_type == ChunkType::Full && self.data == *other
        }
    }

    #[tokio::test]
    async fn process_slice_chunks() {
        let data = vec![1, 2, 3, 4];

        let mut st = process_slice_by_chunks(
            data.as_slice(),
            |_, chunk| ready(Ok(chunk.map(Neg::neg))),
            || 0,
        );

        assert_eq!(&st.next().await.unwrap().await.unwrap(), &[-1, -2]);
        assert_eq!(&st.next().await.unwrap().await.unwrap(), &[-3, -4]);
        assert!(st.next().await.is_none());
        assert!(st.next().await.is_none());
    }

    #[tokio::test]
    async fn process_slice_chunks_empty() {
        let mut st = process_slice_by_chunks(
            &[],
            |_, chunk: ChunkData<i32, 2>| ready(Ok(chunk.map(Neg::neg))),
            || 0,
        );

        assert!(st.next().await.is_none());
    }

    #[tokio::test]
    async fn process_slice_chunks_partial() {
        let data = vec![1, 2, 3];

        let mut st = process_slice_by_chunks(
            data.as_slice(),
            |_, chunk| ready(Ok(chunk.map(Neg::neg))),
            || 7,
        );

        assert_eq!(&st.next().await.unwrap().await.unwrap(), &[-1, -2]);
        assert_eq!(
            st.next().await.unwrap().await.unwrap(),
            Chunk {
                chunk_type: ChunkType::Partial(1),
                data: [-3, -7]
            },
        );
        assert!(st.next().await.is_none());
        assert!(st.next().await.is_none());
    }

    #[tokio::test]
    async fn process_stream_chunks() {
        let data = vec![1, 2, 3, 4];

        let mut st = process_stream_by_chunks(
            stream::iter(data.into_iter().map(Ok)),
            Vec::new(),
            |_, chunk| ready(Ok(chunk.map(Neg::neg))),
            || 0,
        );

        assert_eq!(&st.next().await.unwrap().await.unwrap(), &[-1, -2]);
        assert_eq!(&st.next().await.unwrap().await.unwrap(), &[-3, -4]);
        assert!(st.next().await.is_none());
        assert!(st.next().await.is_none());
    }

    #[tokio::test]
    async fn process_stream_chunks_empty() {
        let mut st = process_stream_by_chunks(
            stream::empty(),
            Vec::new(),
            |_, chunk: Box<[i32; 2]>| ready(Ok(chunk.map(Neg::neg))),
            || 0,
        );

        assert!(!st.is_terminated());
        assert!(st.next().await.is_none());
        assert!(st.is_terminated());
    }

    #[tokio::test]
    async fn process_stream_chunks_partial() {
        let data = vec![1, 2, 3];

        let mut st = process_stream_by_chunks(
            stream::iter(data.into_iter().map(Ok)),
            Vec::new(),
            |_, chunk| ready(Ok(chunk.map(Neg::neg))),
            || 7,
        );

        assert!(!st.is_terminated());
        assert_eq!(&st.next().await.unwrap().await.unwrap(), &[-1, -2]);
        assert!(!st.is_terminated());
        assert_eq!(
            st.next().await.unwrap().await.unwrap(),
            Chunk {
                chunk_type: ChunkType::Partial(1),
                data: [-3, -7]
            },
        );
        assert!(st.is_terminated());
        assert!(st.next().await.is_none() && st.is_terminated());
        assert!(st.next().await.is_none() && st.is_terminated());
    }

    #[tokio::test]
    async fn process_stream_chunks_unfused_whole() {
        // Test that chunk processing stream is fused when the source ends on a chunk boundary.
        let mut i = 0;
        let source = stream::iter(
            iter::from_fn(Box::new(move || {
                let res = match i {
                    0 => Some(0),
                    1 => Some(1),
                    2 => None,
                    _ => panic!("source stream polled after returning None"),
                };
                i += 1;
                res
            }))
            .map(Ok),
        );

        let mut st = process_stream_by_chunks(
            source,
            Vec::new(),
            |_, chunk| ready(Ok(chunk.map(Neg::neg))),
            || 7,
        );

        assert!(!st.is_terminated());
        let Poll::Ready(fut) = poll_immediate(&mut st).next().await.unwrap() else {
            panic!("expected stream to return a future");
        };
        assert_eq!(&fut.await.unwrap(), &[0, -1]);

        assert!(!st.is_terminated()); // Not detected until we poll
        assert!(poll_immediate(&mut st).next().await.is_none() && st.is_terminated());

        // It should still be pending, and it should not try to advance the source iterator again.
        assert!(poll_immediate(&mut st).next().await.is_none() && st.is_terminated());
    }

    #[tokio::test]
    async fn process_stream_chunks_unfused_partial() {
        // Test that chunk processing stream is fused when the source ends with a partial chunk.
        let mut i = 0;
        let source = stream::iter(
            iter::from_fn(Box::new(move || {
                let res = match i {
                    0 => Some(0),
                    1 => Some(1),
                    2 => Some(2),
                    3 => None,
                    _ => panic!("source stream polled after returning None"),
                };
                i += 1;
                res
            }))
            .map(Ok),
        );

        let mut st = process_stream_by_chunks(
            source,
            Vec::new(),
            |_, chunk| ready(Ok(chunk.map(Neg::neg))),
            || 7,
        );

        assert!(!st.is_terminated());
        let Poll::Ready(fut) = poll_immediate(&mut st).next().await.unwrap() else {
            panic!("expected stream to return a future");
        };
        assert_eq!(&fut.await.unwrap(), &[0, -1]);

        assert!(!st.is_terminated());
        let Poll::Ready(fut) = poll_immediate(&mut st).next().await.unwrap() else {
            panic!("expected stream to return a future");
        };
        assert_eq!(
            &fut.await.unwrap(),
            &Chunk {
                chunk_type: ChunkType::Partial(1),
                data: [-2, -7]
            },
        );

        assert!(st.is_terminated());
        // It should be finished, and it should not try to advance the source iterator again.
        assert!(poll_immediate(&mut st).next().await.is_none() && st.is_terminated());
    }

    impl<K, const N: usize> Chunk<K, N> {
        pub fn new(chunk_type: ChunkType, data: K) -> Self {
            Self { chunk_type, data }
        }
    }

    #[test]
    fn chunk_into_iter() {
        assert_eq!(
            Chunk::<_, 2>::new(ChunkType::Full, [1, 2])
                .into_iter()
                .collect::<Vec<_>>(),
            [1, 2],
        );
        assert_eq!(
            Chunk::<_, 2>::new(ChunkType::Partial(1), [3, 4])
                .into_iter()
                .collect::<Vec<_>>(),
            [3],
        );
    }

    #[test]
    fn chunk_unpack() {
        assert_eq!(
            Chunk::<_, 4>::new(ChunkType::Full, vec![[1, 2], [3, 4]]).unpack::<2>(),
            vec![
                Chunk::new(ChunkType::Full, [1, 2]),
                Chunk::new(ChunkType::Full, [3, 4]),
            ],
        );

        assert_eq!(
            Chunk::<_, 4>::new(ChunkType::Partial(3), vec![[1, 2], [3, -1]]).unpack::<2>(),
            vec![
                Chunk::new(ChunkType::Full, [1, 2]),
                Chunk::new(ChunkType::Partial(1), [3, -1]),
            ],
        );

        assert_eq!(
            Chunk::<_, 4>::new(ChunkType::Partial(1), vec![[5, -1]]).unpack::<2>(),
            vec![Chunk::new(ChunkType::Partial(1), [5, -1]),],
        );
    }

    #[test]
    #[should_panic(
        expected = "input to Chunk::unpack (N = 4, M = 2) was not chunked properly. \
                    full input chunk should contain 2 sub-chunks, found 3"
    )]
    fn chunk_unpack_invalid_full() {
        let _ = Chunk::<_, 4>::new(ChunkType::Full, vec![[1, 2], [3, 4], [5, 6]]).unpack::<2>();
    }

    #[test]
    #[should_panic(
        expected = "input to Chunk::unpack (N = 8, M = 2) was not chunked properly. \
                    partial input chunk should contain between 3 and 4 sub-chunks, found 2"
    )]
    fn chunk_unpack_invalid_partial() {
        let _ = Chunk::<_, 8>::new(ChunkType::Partial(5), vec![[1, 2], [3, 4]]).unpack::<2>();
    }

    #[tokio::test]
    async fn flatten_iters() {
        let st = stream::iter([Ok([1, 2]), Ok([3, 4])]);
        assert_eq!(
            st.try_flatten_iters()
                .try_collect::<Vec<u8>>()
                .await
                .unwrap(),
            [1, 2, 3, 4],
        );
    }

    #[tokio::test]
    async fn flatten_iters_error() {
        let st = stream::iter([Ok([1, 2]), Err(Error::Internal), Ok([3, 4])]);
        let res = st
            .try_flatten_iters()
            .collect::<Vec<Result<u8, Error>>>()
            .await;
        assert_eq!(res[0].as_ref().unwrap(), &1);
        assert_eq!(res[1].as_ref().unwrap(), &2);
        assert!(matches!(res[2].as_ref().unwrap_err(), &Error::Internal));

        // The stream should terminate after the first error.
        assert_eq!(res.len(), 3);
    }

    #[tokio::test]
    async fn flatten_iters_is_fused() {
        let mut st = TryFlattenIters::new(stream::iter([Ok([1, 2]), Ok([3, 4])]));
        assert!(st.next().await.is_some());
        assert!(st.next().await.is_some());
        assert!(st.next().await.is_some());
        assert!(st.next().await.is_some());
        assert!(!st.finished);
        assert!(st.next().await.is_none());
        assert!(st.finished);
        assert!(st.next().await.is_none());
        assert!(st.finished);
    }

    #[tokio::test]
    async fn flatten_iters_variable_size() {
        let st = stream::iter([Ok(vec![]), Ok(vec![4]), Ok(vec![5, 6])]);
        assert_eq!(
            st.try_flatten_iters()
                .try_collect::<Vec<u8>>()
                .await
                .unwrap(),
            [4, 5, 6],
        );
    }

    #[tokio::test]
    async fn flatten_iters_unfused_src_pend() {
        let (mut tx, rx) = channel::<Result<FromFn<Box<dyn FnMut() -> Option<u8>>>, Error>>(1);

        let mut st = rx.try_flatten_iters();

        assert!(matches!(
            poll_immediate(&mut st).next().await,
            Some(Poll::Pending)
        ));

        let mut i = 0;
        tx.send(Ok({
            iter::from_fn(Box::new(move || {
                let res = match i {
                    0 => Some(0),
                    1 => Some(1),
                    2 => None,
                    _ => panic!("iterator advanced after returning None"),
                };
                i += 1;
                res
            }))
        }))
        .await
        .unwrap();

        assert!(matches!(
            poll_immediate(&mut st).next().await,
            Some(Poll::Ready(Ok(0)))
        ));

        assert!(matches!(
            poll_immediate(&mut st).next().await,
            Some(Poll::Ready(Ok(1)))
        ));

        assert!(matches!(
            poll_immediate(&mut st).next().await,
            Some(Poll::Pending)
        ));

        // It should still be pending, and it should not try to advance the source iterator again.
        assert!(matches!(
            poll_immediate(&mut st).next().await,
            Some(Poll::Pending)
        ));

        tx.close().await.unwrap();

        assert!(poll_immediate(&mut st).next().await.is_none());
    }

    #[tokio::test]
    async fn flatten_iters_unfused_src_err() {
        let (mut tx, rx) = channel::<Result<FromFn<Box<dyn FnMut() -> Option<u8>>>, Error>>(1);

        let mut st = rx.try_flatten_iters();

        assert!(matches!(
            poll_immediate(&mut st).next().await,
            Some(Poll::Pending)
        ));

        let mut i = 0;
        tx.send(Ok({
            iter::from_fn(Box::new(move || {
                let res = match i {
                    0 => Some(0),
                    1 => Some(1),
                    2 => None,
                    _ => panic!("iterator advanced after returning None"),
                };
                i += 1;
                res
            }))
        }))
        .await
        .unwrap();

        assert!(matches!(
            poll_immediate(&mut st).next().await,
            Some(Poll::Ready(Ok(0)))
        ));

        assert!(matches!(
            poll_immediate(&mut st).next().await,
            Some(Poll::Ready(Ok(1)))
        ));

        tx.send(Err(Error::Internal)).await.unwrap();

        assert!(matches!(
            poll_immediate(&mut st).next().await,
            Some(Poll::Ready(Err(Error::Internal)))
        ));

        // It should now be finished. It should not poll the source iterator again.
        assert!(poll_immediate(&mut st).next().await.is_none());

        tx.close().await.unwrap();

        assert!(poll_immediate(&mut st).next().await.is_none());
    }
}
