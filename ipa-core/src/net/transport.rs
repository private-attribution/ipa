use std::{
    borrow::Borrow,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use futures::{Stream, TryFutureExt};
use pin_project::{pin_project, pinned_drop};

use super::{client::resp_ok, error::ShardError, ConnectionFlavor, Helper, Shard};
use crate::{
    config::{NetworkConfig, ServerConfig},
    executor::IpaRuntime,
    helpers::{
        query::QueryConfig,
        routing::{Addr, RouteId},
        ApiError, BodyStream, HandlerRef, HelperIdentity, HelperResponse, NoQueryId,
        NoResourceIdentifier, NoStep, QueryIdBinding, ReceiveRecords, RequestHandler, RouteParams,
        StepBinding, StreamCollection, Transport, TransportIdentity,
    },
    net::{client::IpaHttpClient, error::Error, IpaHttpServer},
    protocol::{Gate, QueryId},
    sharding::ShardIndex,
    sync::Arc,
};

/// Shared implementation used by [`MpcHttpTransport`] and [`ShardHttpTransport`]
pub struct HttpTransport<F: ConnectionFlavor> {
    pub(super) http_runtime: IpaRuntime,
    pub(super) identity: F::Identity,
    pub(super) clients: Vec<IpaHttpClient<F>>,
    pub(super) record_streams: StreamCollection<F::Identity, BodyStream>,
    pub(super) handler: Option<HandlerRef<F::Identity>>,
}

/// HTTP transport for helper to helper traffic.
#[derive(Clone)]
pub struct MpcHttpTransport {
    pub(super) inner_transport: Arc<HttpTransport<Helper>>,
}

/// A stub for HTTP transport implementation, suitable for serving shard-to-shard traffic
#[derive(Clone)]
pub struct ShardHttpTransport {
    pub(super) inner_transport: Arc<HttpTransport<Shard>>,
    pub(super) shard_count: ShardIndex,
}

impl RouteParams<RouteId, NoQueryId, NoStep> for QueryConfig {
    type Params = String;

    fn resource_identifier(&self) -> RouteId {
        RouteId::ReceiveQuery
    }

    fn query_id(&self) -> NoQueryId {
        NoQueryId
    }

    fn gate(&self) -> NoStep {
        NoStep
    }

    fn extra(&self) -> Self::Params {
        serde_json::to_string(self).unwrap()
    }
}

impl<F: ConnectionFlavor> HttpTransport<F> {
    async fn send<
        D: Stream<Item = Vec<u8>> + Send + 'static,
        Q: QueryIdBinding,
        S: StepBinding,
        R: RouteParams<RouteId, Q, S>,
    >(
        &self,
        dest: F::Identity,
        route: R,
        data: D,
    ) -> Result<(), Error>
    where
        Option<QueryId>: From<Q>,
        Option<Gate>: From<S>,
    {
        let route_id = route.resource_identifier();
        let client_ix = dest.as_index();
        match route_id {
            RouteId::Records => {
                // TODO(600): These fallible extractions aren't really necessary.
                let query_id = <Option<QueryId>>::from(route.query_id())
                    .expect("query_id required when sending records");
                let step =
                    <Option<Gate>>::from(route.gate()).expect("step required when sending records");
                let resp_future = self.clients[client_ix].step(query_id, &step, data)?;
                // Use a dedicated HTTP runtime to poll this future for several reasons:
                // - avoid blocking this task, if the current runtime is overloaded
                // - use the runtime that enables IO (current runtime may not).
                self.http_runtime
                    .spawn(resp_future.map_err(Into::into).and_then(resp_ok))
                    .await?;
                Ok(())
            }
            RouteId::PrepareQuery => {
                let req = serde_json::from_str(route.extra().borrow()).unwrap();
                self.clients[client_ix].prepare_query(req).await
            }
            RouteId::CompleteQuery => {
                let query_id = <Option<QueryId>>::from(route.query_id())
                    .expect("query_id is required to call complete query API");
                self.clients[client_ix].complete_query(query_id).await
            }
            RouteId::QueryStatus => {
                let req = serde_json::from_str(route.extra().borrow())?;
                self.clients[client_ix].status_match(req).await
            }
            evt @ (RouteId::QueryInput
            | RouteId::ReceiveQuery
            | RouteId::KillQuery
            | RouteId::Metrics) => {
                unimplemented!(
                    "attempting to send client-specific request {evt:?} to another helper"
                )
            }
        }
    }

    pub(crate) fn receive<R: RouteParams<NoResourceIdentifier, QueryId, Gate>>(
        &self,
        from: F::Identity,
        route: &R,
    ) -> ReceiveRecords<F::Identity, BodyStream> {
        ReceiveRecords::new(
            (route.query_id(), from, route.gate()),
            self.record_streams.clone(),
        )
    }

    /// Connect an inbound stream of record data.
    ///
    /// This is called by peer entities (shards or helpers) via the HTTP server.
    pub fn receive_stream(
        &self,
        query_id: QueryId,
        gate: Gate,
        from: F::Identity,
        stream: BodyStream,
    ) {
        self.record_streams
            .add_stream((query_id, from, gate), stream);
    }

    /// Dispatches the given request to the [`RequestHandler`] connected to this transport.
    ///
    /// ## Errors
    /// Returns an error, if handler rejects the request for any reason.
    ///
    /// ## Panics
    /// This will panic if request handler hasn't been previously set for this transport.
    pub async fn dispatch<Q: QueryIdBinding, R: RouteParams<RouteId, Q, NoStep>>(
        self: Arc<Self>,
        req: R,
        body: BodyStream,
    ) -> Result<HelperResponse, ApiError>
    where
        Option<QueryId>: From<Q>,
    {
        /// Cleans up the `records_stream` collection after drop to ensure this transport
        /// can process the next query even in case of a panic.
        ///
        /// This implementation is a poor man's safety net and only works because we run
        /// one query at a time and don't use query identifiers.
        #[pin_project(PinnedDrop)]
        struct ClearOnDrop<CF: ConnectionFlavor, F: Future> {
            transport: Arc<HttpTransport<CF>>,
            #[pin]
            inner: F,
        }

        impl<CF: ConnectionFlavor, F: Future> Future for ClearOnDrop<CF, F> {
            type Output = F::Output;

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                self.project().inner.poll(cx)
            }
        }

        #[pinned_drop]
        impl<CF: ConnectionFlavor, F: Future> PinnedDrop for ClearOnDrop<CF, F> {
            fn drop(self: Pin<&mut Self>) {
                self.transport.record_streams.clear();
            }
        }

        let route_id = req.resource_identifier();
        let r = self
            .handler
            .as_ref()
            .expect("A Handler should be set by now")
            .handle(Addr::from_route(None, req), body);

        if let RouteId::CompleteQuery | RouteId::KillQuery = route_id {
            ClearOnDrop {
                transport: Arc::clone(&self),
                inner: r,
            }
            .await
        } else {
            r.await
        }
    }
}

impl MpcHttpTransport {
    #[must_use]
    pub fn new(
        http_runtime: IpaRuntime,
        identity: HelperIdentity,
        server_config: ServerConfig,
        network_config: NetworkConfig<Helper>,
        clients: &[IpaHttpClient<Helper>; 3],
        handler: Option<HandlerRef<HelperIdentity>>,
    ) -> (Self, IpaHttpServer<Helper>) {
        let inner_transport = Arc::new(HttpTransport {
            http_runtime,
            identity,
            clients: clients.to_vec(),
            handler,
            record_streams: StreamCollection::default(),
        });

        let server =
            IpaHttpServer::new_mpc(Arc::clone(&inner_transport), server_config, network_config);
        (Self { inner_transport }, server)
    }

    /// Connect an inbound stream of record data.
    ///
    /// This is called by peer helpers via the HTTP server.
    pub fn receive_stream(
        &self,
        query_id: QueryId,
        gate: Gate,
        from: HelperIdentity,
        stream: BodyStream,
    ) {
        self.inner_transport
            .receive_stream(query_id, gate, from, stream);
    }

    /// Dispatches the given request to the [`RequestHandler`] connected to this transport.
    ///
    /// ## Errors
    /// Returns an error, if handler rejects the request for any reason.
    ///
    /// ## Panics
    /// This will panic if request handler hasn't been previously set for this transport.
    pub async fn dispatch<Q: QueryIdBinding, R: RouteParams<RouteId, Q, NoStep>>(
        &self,
        req: R,
        body: BodyStream,
    ) -> Result<HelperResponse, ApiError>
    where
        Option<QueryId>: From<Q>,
    {
        let t = Arc::clone(&self.inner_transport);
        t.dispatch(req, body).await
    }
}

#[async_trait]
impl Transport for MpcHttpTransport {
    type Identity = HelperIdentity;
    type RecordsStream = ReceiveRecords<Self::Identity, BodyStream>;
    type Error = Error;

    fn identity(&self) -> Self::Identity {
        self.inner_transport.identity
    }

    fn peers(&self) -> impl Iterator<Item = Self::Identity> {
        let this = self.identity();
        HelperIdentity::make_three()
            .into_iter()
            .filter(move |&id| id != this)
    }

    fn peer_count(&self) -> u32 {
        2
    }

    async fn send<
        D: Stream<Item = Vec<u8>> + Send + 'static,
        Q: QueryIdBinding,
        S: StepBinding,
        R: RouteParams<RouteId, Q, S>,
    >(
        &self,
        dest: Self::Identity,
        route: R,
        data: D,
    ) -> Result<(), Error>
    where
        Option<QueryId>: From<Q>,
        Option<Gate>: From<S>,
    {
        self.inner_transport.send(dest, route, data).await
    }

    fn receive<R: RouteParams<NoResourceIdentifier, QueryId, Gate>>(
        &self,
        from: Self::Identity,
        route: R,
    ) -> Self::RecordsStream {
        self.inner_transport.receive(from, &route)
    }
}

impl ShardHttpTransport {
    #[must_use]
    pub fn new(
        http_runtime: IpaRuntime,
        // todo: maybe a wrapper struct for it
        shard_id: ShardIndex,
        shard_count: ShardIndex,
        server_config: ServerConfig,
        network_config: NetworkConfig<Shard>,
        clients: Vec<IpaHttpClient<Shard>>,
        handler: Option<HandlerRef<ShardIndex>>,
    ) -> (Self, IpaHttpServer<Shard>) {
        let inner_transport = Arc::new(HttpTransport {
            http_runtime,
            identity: shard_id,
            clients,
            handler,
            record_streams: StreamCollection::default(),
        });

        let server =
            IpaHttpServer::new_shards(Arc::clone(&inner_transport), server_config, network_config);
        (
            Self {
                inner_transport,
                shard_count,
            },
            server,
        )
    }
}

#[async_trait]
impl Transport for ShardHttpTransport {
    type Identity = ShardIndex;
    type RecordsStream = ReceiveRecords<ShardIndex, BodyStream>;
    type Error = ShardError;

    fn identity(&self) -> Self::Identity {
        self.inner_transport.identity
    }

    fn peers(&self) -> impl Iterator<Item = Self::Identity> {
        let this = self.identity();
        self.shard_count.iter().filter(move |&v| v != this)
    }

    fn peer_count(&self) -> u32 {
        u32::from(self.shard_count).saturating_sub(1)
    }

    async fn send<D, Q, S, R>(
        &self,
        dest: Self::Identity,
        route: R,
        data: D,
    ) -> Result<(), Self::Error>
    where
        Option<QueryId>: From<Q>,
        Option<Gate>: From<S>,
        Q: QueryIdBinding,
        S: StepBinding,
        R: RouteParams<RouteId, Q, S>,
        D: Stream<Item = Vec<u8>> + Send + 'static,
    {
        self.inner_transport
            .send(dest, route, data)
            .map_err(|source| ShardError {
                shard_index: self.identity(),
                source,
            })
            .await
    }

    fn receive<R: RouteParams<NoResourceIdentifier, QueryId, Gate>>(
        &self,
        from: Self::Identity,
        route: R,
    ) -> Self::RecordsStream {
        self.inner_transport.receive(from, &route)
    }
}

#[cfg(all(test, web_test, descriptive_gate))]
mod tests {
    use std::{iter::repeat, task::Poll};

    use bytes::Bytes;
    use futures::stream::{poll_immediate, StreamExt};
    use futures_util::future::{join_all, try_join_all};
    use generic_array::GenericArray;
    use once_cell::sync::Lazy;
    use tokio::sync::mpsc::channel;
    use tokio_stream::wrappers::ReceiverStream;
    use typenum::Unsigned;

    use super::*;
    use crate::{
        ff::{boolean_array::BA64, FieldType, Fp31, Serializable},
        helpers::{
            make_owned_handler,
            query::{
                QueryInput,
                QueryType::{TestMultiply, TestShardedShuffle},
            },
        },
        net::{
            client::ClientIdentity,
            test::{TestConfig, TestConfigBuilder, TestServer},
        },
        secret_sharing::{replicated::semi_honest::AdditiveShare, IntoShares},
        test_fixture::Reconstruct,
        HelperApp,
    };

    static STEP: Lazy<Gate> = Lazy::new(|| Gate::from("http-transport"));

    #[tokio::test]
    async fn clean_on_kill() {
        let noop_handler = make_owned_handler(|_, _| async move {
            {
                Ok(HelperResponse::ok())
            }
        });
        let TestServer { transport, .. } = TestServer::builder()
            .with_request_handler(Arc::clone(&noop_handler))
            .build()
            .await;

        transport.record_streams.add_stream(
            (QueryId, HelperIdentity::ONE, Gate::default()),
            BodyStream::empty(),
        );
        assert_eq!(1, transport.record_streams.len());

        Arc::clone(&transport)
            .dispatch((RouteId::KillQuery, QueryId), BodyStream::empty())
            .await
            .unwrap();

        assert!(transport.record_streams.is_empty());
    }

    #[tokio::test]
    async fn receive_stream() {
        let (tx, rx) = channel::<Result<Bytes, Box<dyn std::error::Error + Send + Sync>>>(1);
        let expected_chunk1 = vec![0u8, 1, 2, 3];
        let expected_chunk2 = vec![255u8, 254, 253, 252];

        let TestServer { transport, .. } = TestServer::default().await;

        let body = BodyStream::from_bytes_stream(ReceiverStream::new(rx));

        // Register the stream with the transport (normally called by step data HTTP API handler)
        transport.receive_stream(QueryId, STEP.clone(), HelperIdentity::TWO, body);

        // Request step data reception (normally called by protocol)
        let mut stream = transport
            .receive(HelperIdentity::TWO, &(QueryId, STEP.clone()))
            .into_bytes_stream();

        // make sure it is not ready as it hasn't received any data yet.
        assert!(matches!(
            poll_immediate(&mut stream).next().await,
            Some(Poll::Pending)
        ));

        // send and verify first chunk
        tx.send(Ok(expected_chunk1.clone().into())).await.unwrap();

        assert_eq!(
            poll_immediate(&mut stream).next().await,
            Some(Poll::Ready(expected_chunk1))
        );

        // send and verify second chunk
        tx.send(Ok(expected_chunk2.clone().into())).await.unwrap();

        assert_eq!(
            poll_immediate(&mut stream).next().await,
            Some(Poll::Ready(expected_chunk2))
        );
    }

    // TODO(651): write a test for an error while reading the body (after error handling is finalized)
    async fn make_helpers(conf: TestConfig) -> Vec<HelperApp> {
        let disable_https = conf.disable_https;
        join_all(
            conf.into_apps()
                .into_iter()
                .map(|a| a.start_app(disable_https)),
        )
        .await
    }

    async fn make_clients_and_helpers(
        conf: TestConfig,
    ) -> (Vec<[IpaHttpClient<Helper>; 3]>, Vec<HelperApp>) {
        let clients = conf
            .rings()
            .map(|test_network| {
                IpaHttpClient::from_conf(
                    &IpaRuntime::current(),
                    &test_network.network,
                    &ClientIdentity::None,
                )
            })
            .collect::<Vec<_>>();

        let helpers = make_helpers(conf).await;

        (clients, helpers)
    }

    async fn test_make_helpers(conf: TestConfig) {
        let (clients, _helpers) = make_clients_and_helpers(conf).await;
        test_multiply_single_shard(&clients).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn happy_case_twice() {
        let conf = TestConfigBuilder::default().build();
        let (clients, _helpers) = make_clients_and_helpers(conf).await;

        test_multiply_single_shard(&clients).await;
        test_multiply_single_shard(&clients).await;
    }

    /// This executes test multiplication protocol by running it exclusively on the leader shards.
    /// If there is more than one shard in the system, they receive no inputs but still participate
    /// by doing the full query cycle. It is backward compatible with traditional 3-party MPC with
    /// no shards.
    ///
    /// The sharding requires some amendments to the test multiplication protocol that are
    /// currently in progress. Once completed, this test can be fixed by fully utilizing all
    /// shards in the system.
    async fn test_multiply_single_shard(clients: &[[IpaHttpClient<Helper>; 3]]) {
        const SZ: usize = <AdditiveShare<Fp31> as Serializable>::Size::USIZE;
        let leader_ring_clients = &clients[0];

        // send a create query command
        let leader_client = &leader_ring_clients[0];
        let create_data = QueryConfig::new(TestMultiply, FieldType::Fp31, 1).unwrap();

        // create query
        let query_id = leader_client.create_query(create_data).await.unwrap();

        // send input
        let a = Fp31::try_from(4u128).unwrap();
        let b = Fp31::try_from(5u128).unwrap();

        let helper_shares = (a, b).share().map(|(a, b)| {
            let mut vec = vec![0u8; 2 * SZ];
            a.serialize(GenericArray::from_mut_slice(&mut vec[..SZ]));
            b.serialize(GenericArray::from_mut_slice(&mut vec[SZ..]));
            BodyStream::from(vec)
        });

        let mut handle_resps = Vec::with_capacity(helper_shares.len());
        for (i, input_stream) in helper_shares.into_iter().enumerate() {
            let data = QueryInput::Inline {
                query_id,
                input_stream,
            };
            handle_resps.push(leader_ring_clients[i].query_input(data));
        }
        try_join_all(handle_resps).await.unwrap();

        // shards receive their own input - in this case empty.
        // convention - first client is shard leader, and we submitted the inputs to it.
        try_join_all(clients.iter().skip(1).map(|ring| {
            try_join_all(ring.each_ref().map(|shard_client| {
                shard_client.query_input(QueryInput::Inline {
                    query_id,
                    input_stream: BodyStream::empty(),
                })
            }))
        }))
        .await
        .unwrap();

        let result: [_; 3] = join_all(leader_ring_clients.each_ref().map(|client| async move {
            let r = client.query_results(query_id).await.unwrap();
            AdditiveShare::<Fp31>::from_byte_slice_unchecked(&r).collect::<Vec<_>>()
        }))
        .await
        .try_into()
        .unwrap();
        let res = result.reconstruct();
        assert_eq!(Fp31::try_from(20u128).unwrap(), res[0]);
    }

    /// Sharded shuffle protocol that runs on multiple shards.
    async fn test_sharded_shuffle(clients: &[[IpaHttpClient<Helper>; 3]]) {
        // Sharded shuffle only works with boolean shares and hardcodes BA64 as the only
        // type it supports
        const ROWS: usize = 20;
        let shards = clients.len();
        let leader_ring_clients = &clients[0];

        // send a create query command
        let leader_client = &leader_ring_clients[0];
        let create_data = QueryConfig::new(TestShardedShuffle, FieldType::Fp31, ROWS).unwrap();

        let query_id = leader_client.create_query(create_data).await.unwrap();

        // send input
        let data = repeat(())
            .enumerate()
            .map(|(i, _)| BA64::try_from(i as u128).unwrap())
            .take(ROWS)
            .collect::<Vec<_>>();
        let helper_shares = data.clone().into_iter().share().map(|helper_shares| {
            helper_shares
                .chunks(ROWS / shards)
                .map(|chunk| BodyStream::from_serializable_iter(chunk.to_vec()))
                .collect::<Vec<_>>()
        });

        let _ =
            try_join_all(helper_shares.into_iter().enumerate().map(
                |(helper, shard_streams)| async move {
                    try_join_all(shard_streams.into_iter().enumerate().map(
                        |(shard, input_stream)| {
                            clients[shard][helper].query_input(QueryInput::Inline {
                                query_id,
                                input_stream,
                            })
                        },
                    ))
                    .await
                },
            ))
            .await
            .unwrap();

        let result: [_; 3] = join_all(leader_ring_clients.each_ref().map(|client| async move {
            let r = client.query_results(query_id).await.unwrap();
            AdditiveShare::<BA64>::from_byte_slice_unchecked(&r).collect::<Vec<_>>()
        }))
        .await
        .try_into()
        .unwrap();
        let res = result.reconstruct();
        assert_eq!(res.len(), data.len());
        assert_ne!(res, data);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn three_helpers_http() {
        let conf = TestConfigBuilder::default()
            .with_disable_https_option(true)
            .build();
        test_make_helpers(conf).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn three_helpers_https() {
        let conf = TestConfigBuilder::default().build();
        test_make_helpers(conf).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn four_shards_http() {
        let conf = TestConfigBuilder::default()
            .with_shard_count(4)
            .with_disable_https_option(true)
            .build();
        test_make_helpers(conf).await;
    }

    #[tokio::test]
    async fn four_shards_http_sharded_shuffle() {
        let conf = TestConfigBuilder::default()
            .with_shard_count(4)
            .with_disable_https_option(true)
            .build();
        let (clients, _helpers) = make_clients_and_helpers(conf).await;
        test_sharded_shuffle(&clients).await;
    }

    #[tokio::test]
    async fn peer_count() {
        fn new_transport<F: ConnectionFlavor>(identity: F::Identity) -> Arc<HttpTransport<F>> {
            Arc::new(HttpTransport {
                http_runtime: IpaRuntime::current(),
                identity,
                clients: Vec::new(),
                handler: None,
                record_streams: StreamCollection::default(),
            })
        }

        assert_eq!(
            2,
            MpcHttpTransport {
                inner_transport: new_transport(HelperIdentity::ONE)
            }
            .peer_count()
        );
        assert_eq!(
            9,
            ShardHttpTransport {
                inner_transport: new_transport(ShardIndex::FIRST),
                shard_count: 10.into()
            }
            .peer_count()
        );
    }
}
