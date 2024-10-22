use std::{
    borrow::Borrow,
    collections::HashMap,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use futures::{Stream, TryFutureExt};
use pin_project::{pin_project, pinned_drop};

use super::{client::resp_ok, ConnectionFlavor, Helper, Shard};
use crate::{
    config::{NetworkConfig, ServerConfig},
    executor::IpaRuntime,
    helpers::{
        query::QueryConfig,
        routing::{Addr, RouteId},
        ApiError, BodyStream, HandlerRef, HelperIdentity, HelperResponse, NoQueryId,
        NoResourceIdentifier, NoStep, QueryIdBinding, ReceiveRecords, RequestHandler, RouteParams,
        StepBinding, StreamCollection, Transport,
    },
    net::{client::MpcHelperClient, error::Error, MpcHelperServer},
    protocol::{Gate, QueryId},
    sharding::ShardIndex,
    sync::Arc,
};

/// Shared implementation used by [`MpcHttpTransport`] and [`ShardHttpTransport`]
pub struct HttpTransport<F: ConnectionFlavor> {
    http_runtime: IpaRuntime,
    identity: F::Identity,
    clients: HashMap<F::Identity, MpcHelperClient<F>>,
    record_streams: StreamCollection<F::Identity, BodyStream>,
    handler: Option<HandlerRef<F::Identity>>,
}

/// HTTP transport for helper to helper traffic.
#[derive(Clone)]
pub struct MpcHttpTransport {
    inner_transport: Arc<HttpTransport<Helper>>,
}

/// A stub for HTTP transport implementation, suitable for serving shard-to-shard traffic
#[derive(Clone)]
pub struct ShardHttpTransport {
    inner_transport: Arc<HttpTransport<Shard>>,
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
        match route_id {
            RouteId::Records => {
                // TODO(600): These fallible extractions aren't really necessary.
                let query_id = <Option<QueryId>>::from(route.query_id())
                    .expect("query_id required when sending records");
                let step =
                    <Option<Gate>>::from(route.gate()).expect("step required when sending records");
                let resp_future = self.clients[&dest].step(query_id, &step, data)?;
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
                self.clients[&dest].prepare_query(req).await
            }
            evt @ (RouteId::QueryInput
            | RouteId::ReceiveQuery
            | RouteId::QueryStatus
            | RouteId::CompleteQuery
            | RouteId::KillQuery) => {
                unimplemented!(
                    "attempting to send client-specific request {evt:?} to another helper"
                )
            }
        }
    }

    fn receive<R: RouteParams<NoResourceIdentifier, QueryId, Gate>>(
        &self,
        from: F::Identity,
        route: &R,
    ) -> ReceiveRecords<F::Identity, BodyStream> {
        ReceiveRecords::new(
            (route.query_id(), from, route.gate()),
            self.record_streams.clone(),
        )
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
        clients: [MpcHelperClient; 3],
        handler: Option<HandlerRef<HelperIdentity>>,
    ) -> (Self, MpcHelperServer<Helper>) {
        let transport = Self::new_internal(http_runtime, identity, clients, handler);
        let server = MpcHelperServer::new_mpc(&transport, server_config, network_config);
        (transport, server)
    }

    fn new_internal(
        http_runtime: IpaRuntime,
        identity: HelperIdentity,
        clients: [MpcHelperClient; 3],
        handler: Option<HandlerRef<HelperIdentity>>,
    ) -> Self {
        let mut id_clients = HashMap::new();
        let [c1, c2, c3] = clients;
        id_clients.insert(HelperIdentity::ONE, c1);
        id_clients.insert(HelperIdentity::TWO, c2);
        id_clients.insert(HelperIdentity::THREE, c3);
        Self {
            inner_transport: Arc::new(HttpTransport {
                http_runtime,
                identity,
                clients: id_clients,
                handler,
                record_streams: StreamCollection::default(),
            }),
        }
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
            .record_streams
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
        identity: ShardIndex,
        server_config: ServerConfig,
        network_config: NetworkConfig<Shard>,
        clients: HashMap<ShardIndex, MpcHelperClient<Shard>>,
        handler: Option<HandlerRef<ShardIndex>>,
    ) -> (Self, MpcHelperServer<Shard>) {
        let transport = Self::new_internal(http_runtime, identity, clients, handler);
        let server = MpcHelperServer::new_shards(&transport, server_config, network_config);
        (transport, server)
    }

    fn new_internal(
        http_runtime: IpaRuntime,
        identity: ShardIndex,
        clients: HashMap<ShardIndex, MpcHelperClient<Shard>>,
        handler: Option<HandlerRef<ShardIndex>>,
    ) -> Self {
        let mut base_clients = HashMap::new();
        for (ix, client) in clients {
            base_clients.insert(ix, client);
        }
        Self {
            inner_transport: Arc::new(HttpTransport {
                http_runtime,
                identity,
                clients: base_clients,
                handler,
                record_streams: StreamCollection::default(),
            }),
        }
    }
}

#[async_trait]
impl Transport for ShardHttpTransport {
    type Identity = ShardIndex;
    type RecordsStream = ReceiveRecords<ShardIndex, BodyStream>;
    type Error = Error;

    fn identity(&self) -> Self::Identity {
        self.inner_transport.identity
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

#[cfg(all(test, web_test, descriptive_gate))]
mod tests {
    use std::{iter::zip, net::TcpListener, task::Poll};

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
        config::{NetworkConfig, ServerConfig},
        ff::{FieldType, Fp31, Serializable},
        helpers::{
            make_owned_handler,
            query::{QueryInput, QueryType::TestMultiply},
        },
        net::{
            client::ClientIdentity,
            test::{get_test_identity, TestConfig, TestConfigBuilder, TestServer},
        },
        secret_sharing::{replicated::semi_honest::AdditiveShare, IntoShares},
        test_fixture::Reconstruct,
        AppConfig, AppSetup, HelperApp,
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

        transport.inner_transport.record_streams.add_stream(
            (QueryId, HelperIdentity::ONE, Gate::default()),
            BodyStream::empty(),
        );
        assert_eq!(1, transport.inner_transport.record_streams.len());

        Transport::clone_ref(&transport)
            .dispatch((RouteId::KillQuery, QueryId), BodyStream::empty())
            .await
            .unwrap();

        assert!(transport.inner_transport.record_streams.is_empty());
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
            .receive(HelperIdentity::TWO, (QueryId, STEP.clone()))
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

    async fn make_helpers(
        sockets: [TcpListener; 3],
        server_config: [ServerConfig; 3],
        network_config: &NetworkConfig<Helper>,
        disable_https: bool,
    ) -> [HelperApp; 3] {
        join_all(
            zip(HelperIdentity::make_three(), zip(sockets, server_config)).map(
                |(id, (socket, server_config))| async move {
                    let identity = if disable_https {
                        ClientIdentity::Header(id)
                    } else {
                        get_test_identity(id)
                    };
                    let (setup, handler) = AppSetup::new(AppConfig::default());
                    let clients = MpcHelperClient::from_conf(
                        &IpaRuntime::current(),
                        network_config,
                        &identity,
                    );
                    let (transport, server) = MpcHttpTransport::new(
                        IpaRuntime::current(),
                        id,
                        server_config.clone(),
                        network_config.clone(),
                        clients,
                        Some(handler),
                    );
                    // TODO: Following is just temporary until Shard Transport is actually used.
                    let shard_clients_config = network_config.client.clone();
                    let shard_server_config = server_config;
                    let shard_network_config =
                        NetworkConfig::new_shards(vec![], shard_clients_config);
                    let (shard_transport, _shard_server) = ShardHttpTransport::new(
                        IpaRuntime::current(),
                        ShardIndex::FIRST,
                        shard_server_config,
                        shard_network_config,
                        HashMap::new(),
                        None,
                    );
                    // ---

                    server
                        .start_on(&IpaRuntime::current(), Some(socket), ())
                        .await;

                    setup.connect(transport, shard_transport)
                },
            ),
        )
        .await
        .try_into()
        .ok()
        .unwrap()
    }

    async fn test_three_helpers(mut conf: TestConfig) {
        let clients = MpcHelperClient::from_conf(
            &IpaRuntime::current(),
            &conf.network,
            &ClientIdentity::None,
        );
        let _helpers = make_helpers(
            conf.sockets.take().unwrap(),
            conf.servers,
            &conf.network,
            conf.disable_https,
        )
        .await;

        test_multiply(&clients).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn happy_case_twice() {
        let mut conf = TestConfigBuilder::with_open_ports().build();
        let clients = MpcHelperClient::from_conf(
            &IpaRuntime::current(),
            &conf.network,
            &ClientIdentity::None,
        );
        let _helpers = make_helpers(
            conf.sockets.take().unwrap(),
            conf.servers,
            &conf.network,
            conf.disable_https,
        )
        .await;

        test_multiply(&clients).await;
        test_multiply(&clients).await;
    }

    async fn test_multiply(clients: &[MpcHelperClient; 3]) {
        const SZ: usize = <AdditiveShare<Fp31> as Serializable>::Size::USIZE;

        // send a create query command
        let leader_client = &clients[0];
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
            let data = QueryInput {
                query_id,
                input_stream,
            };
            handle_resps.push(clients[i].query_input(data));
        }
        try_join_all(handle_resps).await.unwrap();

        let result: [_; 3] = join_all(clients.clone().map(|client| async move {
            let r = client.query_results(query_id).await.unwrap();
            AdditiveShare::<Fp31>::from_byte_slice_unchecked(&r).collect::<Vec<_>>()
        }))
        .await
        .try_into()
        .unwrap();
        let res = result.reconstruct();
        assert_eq!(Fp31::try_from(20u128).unwrap(), res[0]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn three_helpers_http() {
        let conf = TestConfigBuilder::with_open_ports()
            .with_disable_https_option(true)
            .build();
        test_three_helpers(conf).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn three_helpers_https() {
        let conf = TestConfigBuilder::with_open_ports().build();
        test_three_helpers(conf).await;
    }
}
