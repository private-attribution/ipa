use std::future::Future;
use std::io;
use futures::Stream;
use crate::helpers::HelperIdentity;
use crate::helpers::query::QueryConfig;
use crate::protocol::QueryId;
use async_trait::async_trait;

pub trait SendData : Send {
    type Body: Stream<Item = Vec<u8>> + Send;

    fn into(self) -> (String, Self::Body);
}

// pub struct TransportVtable {
//     pub receive_query: fn::<F>(QueryConfig) -> F;
// }

/// Transport that supports per-step channels
#[async_trait]
pub trait ChannelledTransport: Send + Sync + 'static {
    /// Returns the identity of the helper that runs this transport
    fn identity(&self) -> HelperIdentity;

    // fn set_receive_query_cb<C: FnOnce(QueryConfig) -> F, F: Future<Output = Result<QueryId, String>>>(&self, callback: C);

    // /// receive new request to initiate a query.
    // fn receive_query<C: FnOnce(QueryConfig) -> F, F: Future<Output = Result<QueryId, String>>>(&self, callback: C);

    // async fn receive_step() -> (QueryId, ChannelId, Data, CloseRequestFut);

    async fn send<S: SendData>(&self, dest: HelperIdentity, data: S) -> Result<(), io::Error>;
}
