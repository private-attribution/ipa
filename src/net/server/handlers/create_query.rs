use crate::{error::BoxError, ff, net::MpcHelperServerError};
use async_trait::async_trait;
use axum::extract::{BodyStream, FromRequest, Query, RequestParts};
use futures::{ready, Stream};
use hyper::body::{Bytes, HttpBody};
use pin_project::pin_project;
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

/// the size of the field type specified in the query param of the request
/// Possible sizes are are currently from:
/// * `fp2`
/// * `fp31`
/// * `fp32_bit_prime`
struct FieldSize {
    field_size: u32,
}

#[async_trait]
impl<B: Send> FromRequest<B> for FieldSize {
    type Rejection = MpcHelperServerError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        #[cfg_attr(feature = "enable-serde", derive(serde::Deserialize))]
        struct FieldStr {
            field_type: String,
        }

        let Query(FieldStr { field_type }) = req.extract().await?;
        let field_size = ff::size_in_bytes_from_type_str(&field_type)?;

        Ok(Self { field_size })
    }
}

/// Wraps a [`BodyStream`] and produce a new stream that has chunks of exactly size `size_in_bytes`.
/// # Errors
/// If the downstream body is not a multiple of `size_in_bytes`.
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
    pub fn new(body: BodyStream, size_in_bytes: u32) -> Self {
        assert!(size_in_bytes != 0);
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
                // if body is expended, but we have some bytes leftover, error
                None if *this.buffered_size > 0 => {
                    return Poll::Ready(Some(Err(std::io::Error::new::<BoxError>(
                        std::io::ErrorKind::WriteZero,
                        format!(
                            "expected body to align on size {}, but has insufficient bytes {}",
                            *this.size_in_bytes, *this.buffered_size
                        )
                        .into(),
                    ))));
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

#[async_trait]
impl<B: HttpBody<Data = Bytes, Error = hyper::Error> + Send + 'static> FromRequest<B>
    for ByteArrStream
{
    type Rejection = MpcHelperServerError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let FieldSize { field_size } = req.extract().await?;
        let body: BodyStream = req.extract().await?;
        Ok(ByteArrStream::new(body, field_size))
    }
}

#[allow(clippy::unused_async)]
pub async fn handler(_body: ByteArrStream) -> Result<(), MpcHelperServerError> {
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use axum::http::Request;
    use ff::Field;
    use futures_util::{StreamExt, TryStreamExt};
    use hyper::Body;

    async fn to_byte_arr_stream(
        slice: &[u8],
        field_type: &'static str,
    ) -> Result<ByteArrStream, MpcHelperServerError> {
        let b = Body::from(Bytes::from(slice.to_owned()));
        let mut req_parts = RequestParts::new(
            Request::post(format!("/example?field_type={field_type}"))
                .body(b)
                .unwrap(),
        );
        ByteArrStream::from_request(&mut req_parts).await
    }

    #[tokio::test]
    async fn byte_arr_stream_produces_bytes_fp2() {
        let vec = vec![3; 10];
        let stream = to_byte_arr_stream(&vec, ff::Fp2::TYPE_STR).await.unwrap();
        let collected = stream.try_collect::<Vec<_>>().await.unwrap();
        for (expected, got) in vec.chunks(ff::Fp2::SIZE_IN_BYTES as usize).zip(collected) {
            assert_eq!(expected, got.as_ref());
        }
    }

    #[tokio::test]
    async fn byte_arr_stream_produces_bytes_fp32_bit_prime() {
        const ARR_SIZE: usize = 20;
        let vec = vec![7; ARR_SIZE * 10];
        let stream = to_byte_arr_stream(&vec, ff::Fp32BitPrime::TYPE_STR)
            .await
            .unwrap();
        let collected = stream.try_collect::<Vec<_>>().await.unwrap();
        for (expected, got) in vec
            .chunks(ff::Fp32BitPrime::SIZE_IN_BYTES as usize)
            .zip(collected)
        {
            assert_eq!(expected, got.as_ref());
        }
    }

    #[tokio::test]
    async fn byte_arr_stream_fails_with_bad_field_type() {
        let vec = vec![6; 8];
        let stream = to_byte_arr_stream(&vec, "bad_field_type").await;
        assert!(matches!(
            stream,
            Err(MpcHelperServerError::BadQueryString(_))
        ));
    }

    #[tokio::test]
    async fn byte_arr_stream_fails_on_invalid_size() {
        const ARR_SIZE: usize = 2;
        // 1 extra byte
        let vec = vec![4u8; ARR_SIZE * (ff::Fp32BitPrime::SIZE_IN_BYTES as usize) + 1];
        let mut stream = to_byte_arr_stream(&vec, ff::Fp32BitPrime::TYPE_STR)
            .await
            .unwrap();

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
}
