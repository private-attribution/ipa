use crate::{
    helpers::{
        query::QueryCommand,
        transport::{SubscriptionType, Transport, TransportCommand, TransportError},
        CommandEnvelope, HelperIdentity,
    },
    net::{
        client::MpcHelperClient,
        discovery::peer,
        server::{BindTarget, MpcHelperServer},
    },
    protocol::QueryId,
    sync::{Arc, Mutex},
    task::JoinHandle,
};
use async_trait::async_trait;
use std::collections::{hash_map::Entry, HashMap};
use std::net::SocketAddr;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

pub struct HttpTransport {
    id: HelperIdentity,
    peers_conf: Arc<[peer::Config; 3]>,
    subscribe_receiver: Arc<Mutex<Option<mpsc::Receiver<CommandEnvelope>>>>,
    ongoing_queries: Arc<Mutex<HashMap<QueryId, mpsc::Sender<CommandEnvelope>>>>,
    server: MpcHelperServer,
    clients: [MpcHelperClient; 3],
}

impl HttpTransport {
    #[must_use]
    pub fn new(id: HelperIdentity, peers_conf: Arc<[peer::Config; 3]>) -> Arc<Self> {
        let (subscribe_sender, subscribe_receiver) = mpsc::channel(1);
        let ongoing_queries = Arc::new(Mutex::new(HashMap::new()));
        let server = MpcHelperServer::new(subscribe_sender, Arc::clone(&ongoing_queries));
        let clients = MpcHelperClient::from_conf(&peers_conf);
        Arc::new(Self {
            id,
            peers_conf,
            subscribe_receiver: Arc::new(Mutex::new(Some(subscribe_receiver))),
            ongoing_queries,
            server,
            clients,
        })
    }

    /// Binds self to port described in `peers_conf`.
    /// # Panics
    /// if self id not found in `peers_conf`
    pub async fn bind(&self) -> (SocketAddr, JoinHandle<()>) {
        let this_conf = &self.peers_conf[self.id];
        let port = this_conf.origin.port().unwrap();
        let target = BindTarget::Http(format!("0.0.0.0:{}", port.as_str()).parse().unwrap());
        tracing::info!("starting server; binding to port {}", port.as_str());
        self.server.bind(target).await
    }
}

#[async_trait]
impl Transport for Arc<HttpTransport> {
    type CommandStream = ReceiverStream<CommandEnvelope>;

    fn identity(&self) -> HelperIdentity {
        self.id
    }

    async fn subscribe(&self, subscription: SubscriptionType) -> Self::CommandStream {
        match subscription {
            SubscriptionType::QueryManagement => ReceiverStream::new(
                self.subscribe_receiver
                    .lock()
                    .unwrap()
                    .take()
                    .expect("subscribe should only be called once"),
            ),
            SubscriptionType::Query(query_id) => {
                let mut ongoing_queries = self.ongoing_queries.lock().unwrap();
                match ongoing_queries.entry(query_id) {
                    Entry::Occupied(_) => {
                        panic!("attempted to subscribe to commands for query id {}, but there is already a previous subscriber", query_id.as_ref())
                    }
                    Entry::Vacant(entry) => {
                        let (tx, rx) = mpsc::channel(1);
                        entry.insert(tx);
                        ReceiverStream::new(rx)
                    }
                }
            }
        }
    }

    async fn send<C: Send + Into<TransportCommand>>(
        &self,
        destination: HelperIdentity,
        command: C,
    ) -> Result<(), TransportError> {
        let client = &self.clients[destination];
        let command = command.into();
        let command_name = command.name();
        match command {
            TransportCommand::Query(QueryCommand::Prepare(data, resp)) => {
                let query_id = data.query_id;
                client.prepare_query(self.id, data).await.map_err(|inner| {
                    TransportError::SendFailed {
                        command_name: Some(command_name),
                        query_id: Some(query_id),
                        inner: inner.into(),
                    }
                })?;
                // since client has returned, go ahead and respond to query
                resp.send(()).unwrap();
                Ok(())
            }
            TransportCommand::StepData {
                query_id,
                step,
                payload,
                offset,
            } => client
                .step(self.id, query_id, &step, payload, offset)
                .await
                .map_err(|err| TransportError::SendFailed {
                    command_name: Some(command_name),
                    query_id: Some(query_id),
                    inner: err.into(),
                }),
            TransportCommand::Query(
                QueryCommand::Create(_, _)
                | QueryCommand::Input(_, _)
                | QueryCommand::Results(_, _),
            ) => Err(TransportError::ExternalCommandSent { command_name }),
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod e2e_tests {
    use super::*;
    use crate::{
        bits::Serializable,
        ff::{FieldType, Fp31},
        helpers::{
            network::{ChannelId, Network},
            query::{QueryConfig, QueryInput, QueryType},
            transport::ByteArrStream,
            Role, RoleAssignment, MESSAGE_PAYLOAD_SIZE_BYTES,
        },
        net::discovery::PeerDiscovery,
        protocol::Step,
        query::Processor,
        secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, IntoShares},
        test_fixture::{net::localhost_config, Reconstruct},
    };
    use futures::stream::StreamExt;
    use futures_util::{
        future::{join_all, try_join_all},
        join,
    };
    use generic_array::GenericArray;
    use typenum::Unsigned;

    fn open_port() -> u16 {
        std::net::UdpSocket::bind("0.0.0.0:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[tokio::test]
    async fn succeeds_when_subscribed() {
        let expected_query_id = QueryId;
        let expected_message_chunks = (
            ChannelId::new(Role::H1, Step::default().narrow("no-subscribe")),
            vec![0u8; MESSAGE_PAYLOAD_SIZE_BYTES],
        );

        let identities = HelperIdentity::make_three();
        let h1_identity = identities[Role::H1];
        let conf = localhost_config([open_port(), open_port(), open_port()]);
        let transport = HttpTransport::new(h1_identity, Arc::new(conf.peers().clone()));
        transport.bind().await;
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
        let expected_role = Role::H1;
        let expected_step = Step::default().narrow("no-subscribe");
        let expected_payload = vec![0u8; MESSAGE_PAYLOAD_SIZE_BYTES];

        let identities = HelperIdentity::make_three();
        let h1_identity = identities[expected_role];
        let conf = localhost_config([open_port(), open_port(), open_port()]);
        let transport = HttpTransport::new(h1_identity, Arc::new(conf.peers().clone()));
        transport.bind().await;
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
        conf: Arc<[peer::Config; 3]>,
    ) -> [Processor<Arc<HttpTransport>>; 3] {
        join_all(ids.map(|id| {
            let conf = Arc::clone(&conf);
            async move {
                let transport = HttpTransport::new(id, conf);
                transport.bind().await;
                Processor::new(transport, ids).await
            }
        }))
        .await
        .try_into()
        .unwrap()
    }

    fn make_clients(confs: &[peer::Config; 3]) -> [MpcHelperClient; 3] {
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
        let conf = localhost_config([open_port(), open_port(), open_port()]);
        let peers_conf = Arc::new(conf.peers().clone());
        let ids: [HelperIdentity; 3] = [
            HelperIdentity::try_from(1usize).unwrap(),
            HelperIdentity::try_from(2usize).unwrap(),
            HelperIdentity::try_from(3usize).unwrap(),
        ];
        let mut processors = make_processors(ids, Arc::clone(&peers_conf)).await;
        let clients = make_clients(&peers_conf);

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
