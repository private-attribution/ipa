#[cfg(feature = "web-app")]
mod axum_body;
mod box_body;
mod collection;
mod input;

use std::pin::Pin;

#[cfg(feature = "web-app")]
pub use axum_body::WrappedAxumBodyStream;
pub use box_body::WrappedBoxBodyStream;
use bytes::Bytes;
pub use collection::{StreamCollection, StreamKey};
use futures::Stream;
pub use input::{LengthDelimitedStream, RecordsStream, SingleRecordStream};

use crate::error::BoxError;

pub trait BytesStream: Stream<Item = Result<Bytes, BoxError>> + Send {
    /// Collects the entire stream into a vec; only intended for use in tests
    /// # Panics
    /// if the stream has any failure
    #[cfg(test)]
    fn to_vec(self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<u8>> + Send>>
    where
        Self: Sized + 'static,
    {
        use futures::StreamExt;

        Box::pin(self.map(|item| item.unwrap().to_vec()).concat())
    }
}

impl<S: Stream<Item = Result<Bytes, BoxError>> + Send> BytesStream for S {}

pub type BoxBytesStream = Pin<Box<dyn BytesStream>>;

// This type alias serves a few purposes:
//  * Providing a type for input record streams when building without the `web-app` feature.
//    `WrappedBoxBodyStream` is a `Pin<Box<dyn BytesStream>>`.
//  * Reducing the number of places we depend on axum types.
//  * Avoiding an extra level of boxing in the production configuration using axum, since
//    the axum body stream type is already a `Pin<Box<dyn HttpBody>>`.
#[cfg(feature = "in-memory-infra")]
pub type BodyStream = WrappedBoxBodyStream;
#[cfg(feature = "real-world-infra")]
pub type BodyStream = WrappedAxumBodyStream;
