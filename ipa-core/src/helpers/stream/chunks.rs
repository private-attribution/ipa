use std::{
    future::Future,
    iter::Take,
    mem,
    ops::Deref,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Stream, TryStream};
use pin_project::pin_project;

use crate::error::Error;

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

impl ChunkType {
    fn into_chunk<T, const N: usize>(self, data: [T; N]) -> Chunk<T, N> {
        Chunk {
            chunk_type: self,
            data,
        }
    }
}

/// An owned chunk that may be fully or partially valid.
///
/// This type is used for the output data from processing functions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Chunk<T, const N: usize> {
    chunk_type: ChunkType,
    data: [T; N],
}

impl<T, const N: usize> Chunk<T, N> {
    pub fn new(chunk_type: ChunkType, data: [T; N]) -> Self {
        Self { chunk_type, data }
    }
}

impl<T, const N: usize> IntoIterator for Chunk<T, N> {
    type Item = T;
    type IntoIter = Take<<[T; N] as IntoIterator>::IntoIter>;

    fn into_iter(self) -> Self::IntoIter {
        let len = match self.chunk_type {
            ChunkType::Full => N,
            ChunkType::Partial(len) => len,
        };
        self.data.into_iter().take(len)
    }
}

impl<T, const N: usize> AsRef<[T]> for Chunk<T, N> {
    fn as_ref(&self) -> &[T] {
        match self.chunk_type {
            ChunkType::Full => self.data.as_slice(),
            ChunkType::Partial(len) => &self.data[..len],
        }
    }
}

/// Future for a chunk of processed data.
#[pin_project]
pub struct ChunkFuture<T, Fut, const N: usize>
where
    Fut: Future<Output = Result<[T; N], Error>>,
{
    #[pin]
    fut: Fut,
    chunk_type: ChunkType,
}

impl<T, Fut, const N: usize> ChunkFuture<T, Fut, N>
where
    Fut: Future<Output = Result<[T; N], Error>>,
{
    fn new(fut: Fut, chunk_type: ChunkType) -> Self {
        Self { fut, chunk_type }
    }
}

impl<T, Fut, const N: usize> Future for ChunkFuture<T, Fut, N>
where
    Fut: Future<Output = Result<[T; N], Error>>,
{
    type Output = Result<Chunk<T, N>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.fut.poll(cx) {
            Poll::Ready(Ok(data)) => Poll::Ready(Ok(this.chunk_type.into_chunk(data))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Stream returned by `ProcessChunks::process_chunks`.
//
// We could avoid pin projection and instead require that `SliceChunkProcessor` (and its fields) be
// `Unpin`.  Requiring `D: Unpin` is easy, but requiring `F: Unpin` in turn requires a bunch of `C:
// Unpin` bounds in protocols.
#[pin_project]
pub struct SliceChunkProcessor<'a, T, U, F, Fut, D, const N: usize>
where
    T: Clone + 'a,
    F: Fn(usize, ChunkData<'a, T, N>) -> Fut,
    Fut: Future<Output = Result<[U; N], Error>> + 'a,
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

    dummy_fn: D,
}

impl<'a, T, U, F, Fut, D, const N: usize> SliceChunkProcessor<'a, T, U, F, Fut, D, N>
where
    T: Clone,
    F: Fn(usize, ChunkData<'a, T, N>) -> Fut,
    Fut: Future<Output = Result<[U; N], Error>> + 'a,
    D: Fn() -> T,
{
    fn next_chunk(self: Pin<&mut Self>) -> Option<ChunkFuture<U, Fut, N>> {
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
            last_chunk.resize_with(N, this.dummy_fn);
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

impl<'a, T, U, F, Fut, D, const N: usize> Stream for SliceChunkProcessor<'a, T, U, F, Fut, D, N>
where
    T: Clone,
    F: Fn(usize, ChunkData<'a, T, N>) -> Fut,
    Fut: Future<Output = Result<[U; N], Error>> + 'a,
    D: Fn() -> T,
{
    type Item = ChunkFuture<U, Fut, N>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.next_chunk())
    }
}

/// Trait for processing data by chunks.
pub trait ProcessChunks<'a, T: Clone, const N: usize> {
    /// Process data by chunks.
    ///
    /// This method returns a stream that will invoke `process_fn` for `N` records at a time,
    /// returning the resulting processed chunks. If the input length is not a multiple of `N`,
    /// `dummy_fn` is used to generate records to complete the last chunk.
    fn process_chunks<U, F, Fut, D>(
        self,
        process_fn: F,
        dummy_fn: D,
    ) -> SliceChunkProcessor<'a, T, U, F, Fut, D, N>
    where
        F: Fn(usize, ChunkData<'a, T, N>) -> Fut,
        Fut: Future<Output = Result<[U; N], Error>> + 'a,
        D: Fn() -> T;
}

impl<'a, T: Clone, const N: usize> ProcessChunks<'a, T, N> for &'a [T] {
    fn process_chunks<U, F, Fut, D>(
        self,
        process_fn: F,
        dummy_fn: D,
    ) -> SliceChunkProcessor<'a, T, U, F, Fut, D, N>
    where
        F: Fn(usize, ChunkData<'a, T, N>) -> Fut,
        Fut: Future<Output = Result<[U; N], Error>> + 'a,
        D: Fn() -> T,
    {
        SliceChunkProcessor {
            slice: self,
            pos: 0,
            remainder_len: self.len() % N,
            process_fn,
            dummy_fn,
        }
    }
}

/// Trait to flatten a stream of iterables.
pub trait TryFlattenItersExt: TryStream {
    /// Flatten a `TryStream` of `IntoIterator`s.
    ///
    /// Similar to `TryStream::try_flatten`, but that flattens a `TryStream` of `TryStream`s.
    fn try_flatten_iters<T, I>(self) -> TryFlattenIters<T, I, Self>
    where
        I: IntoIterator<Item = T>,
        Self: Stream<Item = Result<I, Error>> + Sized;
}

impl<St: TryStream> TryFlattenItersExt for St {
    fn try_flatten_iters<T, I>(self) -> TryFlattenIters<T, I, Self>
    where
        I: IntoIterator<Item = T>,
        Self: Stream<Item = Result<I, Error>> + Sized,
    {
        TryFlattenIters {
            stream: self,
            iter: None,
            finished: false,
        }
    }
}

/// Stream returned by `TryFlattenIters::try_flatten_iters`.
#[pin_project]
pub struct TryFlattenIters<T, I, St>
where
    I: IntoIterator<Item = T>,
    St: Stream<Item = Result<I, Error>>,
{
    #[pin]
    stream: St,
    iter: Option<<I as IntoIterator>::IntoIter>,
    finished: bool,
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
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
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

    impl<T, const N: usize> PartialEq<[T; N]> for Chunk<T, N>
    where
        [T; N]: PartialEq<[T; N]>,
    {
        fn eq(&self, other: &[T; N]) -> bool {
            self.chunk_type == ChunkType::Full && self.data == *other
        }
    }

    impl<T: PartialEq, const N: usize> PartialEq<[T]> for Chunk<T, N> {
        fn eq(&self, other: &[T]) -> bool {
            if self.chunk_type == ChunkType::Full && other.len() != N {
                return false;
            }
            self.data[..other.len()] == *other
        }
    }

    #[tokio::test]
    async fn process_chunks() {
        let data = vec![1, 2, 3, 4];

        let mut st = data
            .as_slice()
            .process_chunks(|_, chunk| ready(Ok(chunk.map(Neg::neg))), || 0);

        assert_eq!(&st.next().await.unwrap().await.unwrap(), &[-1, -2]);
        assert_eq!(&st.next().await.unwrap().await.unwrap(), &[-3, -4]);
        assert!(st.next().await.is_none());
        assert!(st.next().await.is_none());
    }

    #[tokio::test]
    async fn process_chunks_partial() {
        let data = vec![1, 2, 3];

        let mut st = data
            .as_slice()
            .process_chunks(|_, chunk| ready(Ok(chunk.map(Neg::neg))), || 7);

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

    #[test]
    fn chunk_into_iter() {
        assert_eq!(
            Chunk::new(ChunkType::Full, [1, 2])
                .into_iter()
                .collect::<Vec<_>>(),
            [1, 2],
        );
        assert_eq!(
            Chunk::new(ChunkType::Partial(1), [3, 4])
                .into_iter()
                .collect::<Vec<_>>(),
            [3],
        );
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
        assert_eq!(res[3].as_ref().unwrap(), &3);
        assert_eq!(res[4].as_ref().unwrap(), &4);
    }

    #[tokio::test]
    async fn flatten_iters_is_fused() {
        let mut st = stream::iter([Ok([1, 2]), Ok([3, 4])]).try_flatten_iters();
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
                    _ => panic!("called after returning None"),
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
                    _ => panic!("called after returning None"),
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

        // It should now be pending. It should not poll the source iterator again.
        assert!(matches!(
            poll_immediate(&mut st).next().await,
            Some(Poll::Pending)
        ));

        tx.close().await.unwrap();

        assert!(poll_immediate(&mut st).next().await.is_none());
    }
}
