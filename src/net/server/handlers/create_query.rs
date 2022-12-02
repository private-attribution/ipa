use crate::{
    ff::{self, Field},
    net::MpcHelperServerError,
};
use async_trait::async_trait;
use axum::{
    body::{Bytes, HttpBody},
    extract::{BodyStream, FromRequest, Query, RequestParts},
};
use futures::{ready, Stream};
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// the string repr of the field type from the query param of the request
/// Possible values are currently:
/// * `fp2`
/// * `fp31`
/// * `fp32_bit_prime`
#[cfg_attr(feature = "enable-serde", derive(serde::Deserialize))]
struct FieldStr {
    field_type: String,
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
    buffered: Vec<Bytes>,
}

impl ByteArrStream {
    pub fn new(body: BodyStream, size_in_bytes: u32) -> Self {
        Self {
            body,
            size_in_bytes,
            buffered_size: 0,
            buffered: Vec::new(),
        }
    }

    /// returns [`Bytes`] of `size_in_bytes` length from the buffered chunks
    /// # Panics
    /// if the total length of byte buffers is smaller than `size_in_bytes`
    fn take_bytes(size_in_bytes: u32, buffered: &mut Vec<Bytes>, buffered_size: &mut u32) -> Bytes {
        assert!(*buffered_size >= size_in_bytes);

        // take from single buffer
        // simply splits the first buffer in-place
        if buffered[0].len() > size_in_bytes as usize {
            let out_bytes = buffered[0].split_to(size_in_bytes as usize);
            *buffered_size -= size_in_bytes;
            out_bytes
        } else {
            // take across buffers
            // removes expended buffers after taking
            let mut out_bytes = Vec::new();
            let mut remaining_bytes = size_in_bytes as usize;
            let mut i = 0;
            loop {
                if remaining_bytes == 0 {
                    break;
                }
                let buffer = &mut buffered[i];
                let buffer_len = buffer.len();
                // current `buffer` has more bytes than needed
                if buffer_len > remaining_bytes {
                    out_bytes.push(buffer.split_to(remaining_bytes));
                    remaining_bytes = 0;
                } else {
                    // current `buffer` has <= bytes needed, needs removal
                    out_bytes.push(buffer.clone());
                    i += 1;
                    remaining_bytes -= buffer.len();
                }
            }

            // remove expended buffers
            buffered.drain(0..i);
            // reduce size of total buffers accordingly
            *buffered_size -= size_in_bytes;
            // create new `Bytes` that combines chunks
            let bytes_vec = out_bytes.into_iter().fold(
                Vec::with_capacity(size_in_bytes as usize),
                |mut acc, n| {
                    acc.extend_from_slice(&n);
                    acc
                },
            );
            Bytes::from(bytes_vec)
        }
    }
}

impl Stream for ByteArrStream {
    type Item = Result<Bytes, MpcHelperServerError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.as_mut().project();
        loop {
            // if we currently have enough bytes, return them
            if *this.buffered_size >= *this.size_in_bytes {
                return Poll::Ready(Some(Ok(Self::take_bytes(
                    *this.size_in_bytes,
                    this.buffered,
                    this.buffered_size,
                ))));
            }
            // if we need more bytes, poll the body
            #[allow(clippy::cast_possible_truncation)] // bytes size will not exceed u32
            match ready!(this.body.as_mut().poll_next(cx)) {
                // if body is expended, but we have some bytes leftover, error
                None if *this.buffered_size > 0 => {
                    return Poll::Ready(Some(Err(MpcHelperServerError::WrongBodyLen {
                        body_len: *this.buffered_size,
                        element_size: *this.size_in_bytes as usize,
                    })));
                }
                // if body is finished, this stream is finished
                None => return Poll::Ready(None),
                // if body produces error, forward the error
                Some(Err(err)) => return Poll::Ready(Some(Err(err.into()))),
                // if body has more bytes, push it into the buffer and loop
                Some(Ok(bytes)) => {
                    *this.buffered_size += bytes.len() as u32;
                    this.buffered.push(bytes);
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
        let Query(FieldStr { field_type }) = req.extract().await?;
        let body: BodyStream = req.extract().await?;
        match field_type.as_str() {
            ff::Fp2::STR_REPR => Ok(ByteArrStream::new(body, ff::Fp2::SIZE_IN_BYTES)),
            ff::Fp31::STR_REPR => Ok(ByteArrStream::new(body, ff::Fp31::SIZE_IN_BYTES)),
            ff::Fp32BitPrime::STR_REPR => {
                Ok(ByteArrStream::new(body, ff::Fp32BitPrime::SIZE_IN_BYTES))
            }
            other => Err(MpcHelperServerError::bad_query_value(&field_type, other)),
        }
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
    use futures_util::{StreamExt, TryStreamExt};
    use hyper::Body;
    use rand::distributions::Uniform;
    use rand::{thread_rng, Rng};
    use rand_core::{CryptoRng, RngCore};

    fn random_vec<R: RngCore + CryptoRng>(rng: &mut R, len: usize) -> Vec<u8> {
        let range = Uniform::from(0..u8::MAX);
        rng.sample_iter(&range).take(len).collect()
    }

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
        let vec = random_vec(&mut thread_rng(), 10);
        let stream = to_byte_arr_stream(&vec, ff::Fp2::STR_REPR).await.unwrap();
        let collected = stream.try_collect::<Vec<_>>().await.unwrap();
        for (expected, got) in vec.chunks(ff::Fp2::SIZE_IN_BYTES as usize).zip(collected) {
            assert_eq!(expected, got.as_ref());
        }
    }

    #[tokio::test]
    async fn byte_arr_stream_produces_bytes_fp32_bit_prime() {
        const ARR_SIZE: usize = 20;
        let vec = random_vec(&mut thread_rng(), ARR_SIZE * 10);
        let stream = to_byte_arr_stream(&vec, ff::Fp32BitPrime::STR_REPR)
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
        let vec = random_vec(&mut thread_rng(), 8);
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
        let mut stream = to_byte_arr_stream(&vec, ff::Fp32BitPrime::STR_REPR)
            .await
            .unwrap();

        // valid values
        for _ in 0..ARR_SIZE {
            stream.next().await;
        }
        let failed = stream.next().await;
        assert!(
            matches!(failed, Some(Err(MpcHelperServerError::WrongBodyLen { .. }))),
            "actually got {failed:?}"
        );
    }
}
