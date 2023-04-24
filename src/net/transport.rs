use crate::{
    config::{NetworkConfig, ServerConfig},
    helpers::{
        HelperIdentity, NoResourceIdentifier, QueryIdBinding, RouteId, RouteParams, StepBinding,
        Transport, TransportCallbacks,
    },
    net::{client::MpcHelperClient, error::Error},
    protocol::{QueryId, Step},
    sync::Arc,
    task::JoinHandle,
};
use async_trait::async_trait;
use futures::{Stream, TryFutureExt};
use std::{
    borrow::Borrow,
    net::{SocketAddr, TcpListener},
};
use tokio_stream::Empty;

pub struct HttpTransport {
    identity: HelperIdentity,
    _conf: Arc<NetworkConfig>,
    #[cfg(never)]
    subscribe_receiver: Arc<Mutex<Option<mpsc::Receiver<CommandEnvelope>>>>,
    #[cfg(never)]
    ongoing_queries: Arc<Mutex<HashMap<QueryId, mpsc::Sender<CommandEnvelope>>>>,
    #[cfg(never)]
    server: MpcHelperServer,
    clients: [MpcHelperClient; 3],
}

impl HttpTransport {
    #[must_use]
    #[allow(clippy::needless_pass_by_value)] // TODO: remove when ServerConfig is used
    pub fn new(
        identity: HelperIdentity,
        _server_conf: ServerConfig,
        network_conf: Arc<NetworkConfig>,
        _callbacks: TransportCallbacks<Arc<Self>>,
    ) -> Arc<Self> {
        #[cfg(never)]
        let (subscribe_sender, subscribe_receiver) = mpsc::channel(1);
        #[cfg(never)]
        let ongoing_queries = Arc::new(Mutex::new(HashMap::new()));
        #[cfg(never)]
        let server = MpcHelperServer::new(subscribe_sender, Arc::clone(&ongoing_queries));
        let clients = MpcHelperClient::from_conf(&network_conf);
        Arc::new(Self {
            identity,
            _conf: network_conf,
            #[cfg(never)]
            subscribe_receiver: Arc::new(Mutex::new(Some(subscribe_receiver))),
            #[cfg(never)]
            ongoing_queries,
            #[cfg(never)]
            server,
            clients,
        })
    }

    #[allow(clippy::missing_panics_doc, clippy::unused_async)] // TODO: temporary
    pub async fn from_tcp(&self, _socket: TcpListener) {
        /*
        tracing::info!("starting server");
        self.server.bind(BindTarget::HttpListener(socket)).await;
        */
        todo!(); // TODO(server)
    }

    /// Binds self to port described in `peers_conf`.
    /// # Panics
    /// if self id not found in `peers_conf`
    #[allow(clippy::unused_async)] // TODO: temporary
    pub async fn bind(&self) -> (SocketAddr, JoinHandle<()>) {
        /*
        let this_conf = &self.conf.peers()[self.id];
        let port = this_conf.origin.port().unwrap();
        let target = BindTarget::Http(format!("0.0.0.0:{}", port.as_str()).parse().unwrap());
        tracing::info!("starting server; binding to port {}", port.as_str());
        self.server.bind(target).await
        */
        todo!(); // TODO(server)
    }
}

#[async_trait]
impl Transport for Arc<HttpTransport> {
    type RecordsStream = Empty<Vec<u8>>; // TODO(server): resolve placeholder
    type Error = Error;

    fn identity(&self) -> HelperIdentity {
        self.identity
    }

    async fn send<
        D: Stream<Item = Vec<u8>> + Send + 'static,
        Q: QueryIdBinding,
        S: StepBinding,
        R: RouteParams<RouteId, Q, S>,
    >(
        &self,
        dest: HelperIdentity,
        route: R,
        data: D,
    ) -> Result<(), Error>
    where
        Option<QueryId>: From<Q>,
        Option<Step>: From<S>,
    {
        let route_id = route.resource_identifier();
        match route_id {
            RouteId::Records => {
                // TODO(600): These fallible extractions aren't really necessary.
                let query_id = <Option<QueryId>>::from(route.query_id())
                    .expect("query_id required when sending records");
                let step =
                    <Option<Step>>::from(route.step()).expect("step required when sending records");
                let resp_future = self.clients[dest].step(dest, query_id, &step, data)?;
                tokio::spawn(async move {
                    resp_future
                        .map_err(Into::into)
                        .and_then(MpcHelperClient::resp_ok)
                        .await
                        .expect("failed to stream records");
                });
                // TODO(600): We need to do something better than panic if there is an error sending the
                // data. Note, also, that the caller of this function (`GatewayBase::get_sender`)
                // currently panics on errors.
                Ok(())
            }
            RouteId::PrepareQuery => {
                let req = serde_json::from_str(route.extra().borrow()).unwrap();
                self.clients[dest].prepare_query(self.identity, req).await
            }
            RouteId::ReceiveQuery => {
                unimplemented!("attempting to send ReceiveQuery to another helper")
            }
        }
    }

    fn receive<R: RouteParams<NoResourceIdentifier, QueryId, Step>>(
        &self,
        _from: HelperIdentity,
        _route: R,
    ) -> Self::RecordsStream {
        /*
        ReceiveRecords::new(
            (route.query_id(), from, route.step()),
            self.record_streams.clone(),
        )
        */
        todo!() // TODO(server)
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
#[cfg(never)]
mod e2e_tests {
    use std::{iter::zip, net::TcpListener};

    use super::*;
    use crate::{
        config::PeerConfig,
        ff::{FieldType, Fp31, Serializable},
        helpers::{
            network::{ChannelId, Network},
            query::{QueryConfig, QueryInput, QueryType},
            transport::ByteArrStream,
            Role, RoleAssignment, MESSAGE_PAYLOAD_SIZE_BYTES,
        },
        protocol::Step,
        query::Processor,
        secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, IntoShares},
        test_fixture::{config::TestConfigBuilder, Reconstruct},
    };
    use futures::stream::StreamExt;
    use futures_util::{
        future::{join_all, try_join_all},
        join,
    };
    use generic_array::GenericArray;
    use typenum::Unsigned;

    fn select_first<T>(value: [T; 3]) -> T {
        let [first, _, _] = value;
        first
    }

    #[tokio::test]
    async fn succeeds_when_subscribed() {
        let expected_query_id = QueryId;
        let expected_message_chunks = (
            ChannelId::new(Role::H1, Step::default().narrow("no-subscribe")),
            vec![0u8; MESSAGE_PAYLOAD_SIZE_BYTES],
        );

        let identities = HelperIdentity::make_three();
        let h1_index = 0usize;
        let h1_identity = identities[h1_index];
        let mut conf = TestConfigBuilder::with_open_ports().build();
        let transport = HttpTransport::new(
            h1_identity,
            conf.servers[h1_index].clone(),
            Arc::new(conf.network),
        );
        let socket = select_first(conf.sockets.take().unwrap());
        transport.from_tcp(socket).await;
        let network = Network::new(
            Arc::clone(&transport),
            expected_query_id,
            RoleAssignment::new(identities),
        );
        let mut message_chunks_stream = network.recv_stream().await;

        let command = TransportCommand::StepData {
            query_id: expected_query_id,
            step: expected_message_chunks.0.step.clone(),
            payload: expected_message_chunks.1.clone(),
            offset: 0,
        };
        let res = transport.send(h1_identity, command).await;
        assert!(matches!(res, Ok(())));

        let message_chunks = message_chunks_stream.next().await;
        assert_eq!(message_chunks, Some(expected_message_chunks));
    }

    #[tokio::test]
    async fn fails_if_not_subscribed() {
        let expected_query_id = QueryId;
        let expected_step = Step::default().narrow("no-subscribe");
        let expected_payload = vec![0u8; MESSAGE_PAYLOAD_SIZE_BYTES];

        let identities = HelperIdentity::make_three();
        let h1_index = 0;
        let h1_identity = identities[h1_index];
        let mut conf = TestConfigBuilder::with_open_ports().build();
        let transport = HttpTransport::new(
            h1_identity,
            conf.servers[h1_index].clone(),
            Arc::new(conf.network),
        );
        let socket = select_first(conf.sockets.take().unwrap());
        transport.from_tcp(socket).await;
        let command = TransportCommand::StepData {
            query_id: expected_query_id,
            step: expected_step.clone(),
            payload: expected_payload.clone(),
            offset: 0,
        };

        // with the below code missing, there will be nothing listening for data for this `QueryId`.
        // Since there aren't any subscribers for this data, it should fail to send:
        // let network = Network::new(
        //     Arc::clone(&transport),
        //     expected_query_id,
        //     RoleAssignment::new(identities),
        // );
        // let mut message_chunks_stream = network.recv_stream().await;

        let res = transport.send(h1_identity, command).await;
        assert!(res.unwrap_err().to_string().contains("query id not found"));
    }

    async fn make_processors(
        ids: [HelperIdentity; 3],
        sockets: [TcpListener; 3],
        server_conf: [ServerConfig; 3],
        network_conf: Arc<NetworkConfig>,
    ) -> [Processor<Arc<HttpTransport>>; 3] {
        let network_conf = &network_conf;
        join_all(zip(ids, zip(sockets, server_conf)).map(
            |(id, (socket, server_conf))| async move {
                let transport = HttpTransport::new(id, server_conf, Arc::clone(network_conf));
                transport.from_tcp(socket).await;
                Processor::new(transport).await
            },
        ))
        .await
        .try_into()
        .unwrap()
    }

    fn make_clients(confs: &[PeerConfig; 3]) -> [MpcHelperClient; 3] {
        confs
            .iter()
            .map(|conf| MpcHelperClient::new(conf.origin.clone()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    async fn handle_all_next(processors: &mut [Processor<Arc<HttpTransport>>; 3]) {
        let mut handles = Vec::with_capacity(processors.len());
        for processor in processors {
            handles.push(processor.handle_next());
        }
        join_all(handles).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn happy_case() {
        const SZ: usize = <Replicated<Fp31> as Serializable>::Size::USIZE;
        let mut conf = TestConfigBuilder::with_open_ports().build();
        let ids: [HelperIdentity; 3] = [
            HelperIdentity::try_from(1usize).unwrap(),
            HelperIdentity::try_from(2usize).unwrap(),
            HelperIdentity::try_from(3usize).unwrap(),
        ];
        let clients = make_clients(conf.network.peers());
        let mut processors = make_processors(
            ids,
            conf.sockets.take().unwrap(),
            conf.servers,
            Arc::new(conf.network),
        )
        .await;

        // send a create query command
        let leader_client = &clients[0];
        let create_data = QueryConfig {
            field_type: FieldType::Fp31,
            query_type: QueryType::TestMultiply,
        };

        // create query
        let create_query = leader_client.create_query(create_data);
        let handle_next = handle_all_next(&mut processors);
        let (query_id, _) = join!(create_query, handle_next);

        let query_id = query_id.unwrap();

        // send input
        let a = Fp31::from(4u128);
        let b = Fp31::from(5u128);

        let helper_shares = (a, b).share().map(|(a, b)| {
            let mut vec = vec![0u8; 2 * SZ];
            a.serialize(GenericArray::from_mut_slice(&mut vec[..SZ]));
            b.serialize(GenericArray::from_mut_slice(&mut vec[SZ..]));
            ByteArrStream::from(vec)
        });

        let mut handle_resps = Vec::with_capacity(helper_shares.len());
        for (i, input_stream) in helper_shares.into_iter().enumerate() {
            let data = QueryInput {
                query_id,
                input_stream,
            };
            handle_resps.push(clients[i].query_input(data));
        }
        let handle_next = handle_all_next(&mut processors);
        let (resps, _) = join!(try_join_all(handle_resps), handle_next);
        resps.unwrap();

        let result: [_; 3] = join_all(processors.map(|mut processor| async move {
            let r = processor.complete(query_id).await.unwrap().into_bytes();
            Replicated::<Fp31>::from_byte_slice(&r).collect::<Vec<_>>()
        }))
        .await
        .try_into()
        .unwrap();

        let res = result.reconstruct();
        assert_eq!(Fp31::from(20u128), res[0]);
    }
}
