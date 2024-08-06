use std::{
    pin::Pin,
    task::{Context, Poll},
};

use axum::body::{Body, BodyDataStream};
use bytes::Bytes;
use futures::{Stream, StreamExt};
use pin_project::pin_project;

use crate::{error::BoxError, helpers::BytesStream};

/// This struct is a simple wrapper so that both in-memory-infra and real-world-infra have a
/// unified interface for streams consumed by transport layer.
#[pin_project]
pub struct WrappedAxumBodyStream(#[pin] BodyDataStream);

impl WrappedAxumBodyStream {
    pub(super) fn new(b: Body) -> Self {
        Self(b.into_data_stream())
    }

    #[must_use]
    pub fn empty() -> Self {
        Self::new(Body::empty())
    }

    pub fn from_bytes_stream<S: BytesStream + 'static>(stream: S) -> Self {
        Self::new(axum::body::Body::from_stream(stream))
    }
}

impl Stream for WrappedAxumBodyStream {
    type Item = Result<Bytes, BoxError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut inner = self.project().0;
        inner.poll_next_unpin(cx).map_err(BoxError::from)
    }
}

#[async_trait::async_trait]
impl<S> axum::extract::FromRequest<S> for WrappedAxumBodyStream
where
    S: Send + Sync,
{
    type Rejection = crate::net::Error;

    async fn from_request(
        req: axum::extract::Request,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self::new(req.into_body()))
    }
}
