use crate::{
    helpers::{
        query::QueryCommand,
        transport::{
            http::{
                client::MpcHelperClient,
                discovery::peer,
                server::{BindTarget, MpcHelperServer},
            },
            Error, SubscriptionType, Transport, TransportCommand,
        },
        CommandEnvelope, HelperIdentity,
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
    peers_conf: Arc<HashMap<HelperIdentity, peer::Config>>,
    subscribe_receiver: Arc<Mutex<Option<mpsc::Receiver<CommandEnvelope>>>>,
    ongoing_queries: Arc<Mutex<HashMap<QueryId, mpsc::Sender<CommandEnvelope>>>>,
    server: MpcHelperServer,
    clients: HashMap<HelperIdentity, MpcHelperClient>,
}

impl HttpTransport {
    #[must_use]
    pub fn new(
        id: HelperIdentity,
        peers_conf: Arc<HashMap<HelperIdentity, peer::Config>>,
    ) -> Arc<Self> {
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
        let this_conf = self
            .peers_conf
            .get(&self.id)
            .unwrap_or_else(|| panic!("HelperIdentity {:?} not found in config", self.id));
        let port = this_conf.origin.port().unwrap();
        let target = BindTarget::Http(format!("127.0.0.1:{}", port.as_str()).parse().unwrap());
        tracing::info!("starting server; binding to port {}", port.as_str());
        self.server.bind(target).await
    }
}

#[async_trait]
impl Transport for Arc<HttpTransport> {
    type CommandStream = ReceiverStream<CommandEnvelope>;

    fn identity(&self) -> HelperIdentity {
        self.id.clone()
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
        destination: &HelperIdentity,
        command: C,
    ) -> Result<(), Error> {
        let client = self
            .clients
            .get(destination)
            .ok_or_else(|| Error::UnknownHelper(destination.clone()))?;
        let command = command.into();
        let command_name = command.name();
        match command {
            TransportCommand::Query(QueryCommand::Prepare(data, resp)) => {
                let query_id = data.query_id;
                client
                    .prepare_query(&self.id, data)
                    .await
                    .map_err(|inner| Error::SendFailed {
                        command_name: Some(command_name),
                        query_id: Some(query_id),
                        inner: inner.into(),
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
                .step(&self.id, query_id, step, payload, offset)
                .await
                .map_err(|err| Error::SendFailed {
                    command_name: Some(command_name),
                    query_id: Some(query_id),
                    inner: err.into(),
                }),
            TransportCommand::Query(QueryCommand::Create(_, _) | QueryCommand::Input(_, _)) => {
                Err(Error::ExternalCommandSent { command_name })
            }
        }
    }
}

#[cfg(test)]
mod e2e_tests {
    use super::*;
    use crate::{
        ff::FieldType,
        helpers::{
            query::{QueryConfig, QueryType},
            transport::http::discovery::PeerDiscovery,
        },
        query::Processor,
        test_fixture::net::localhost_config_map,
    };
    use futures_util::join;

    fn open_port() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    async fn make_processors(
        conf: Arc<HashMap<HelperIdentity, peer::Config>>,
    ) -> [Processor<Arc<HttpTransport>>; 3] {
        let ids: [HelperIdentity; 3] = [
            HelperIdentity::try_from(1usize).unwrap(),
            HelperIdentity::try_from(2usize).unwrap(),
            HelperIdentity::try_from(3usize).unwrap(),
        ];

        let mut processors = Vec::with_capacity(ids.len());
        for this_id in ids.clone() {
            let transport = HttpTransport::new(this_id.clone(), Arc::clone(&conf));
            transport.bind().await;
            let processor = Processor::new(transport, ids.clone()).await;
            processors.push(processor);
        }
        processors.try_into().unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn happy_case() {
        let conf = localhost_config_map([open_port(), open_port(), open_port()]);
        let peers_conf = Arc::new(conf.peers_map().clone());
        let [mut leader_processor, mut follower1_processor, mut follower2_processor] =
            make_processors(Arc::clone(&peers_conf)).await;
        // send a create query command
        let leader_id = HelperIdentity::try_from(1usize).unwrap();

        let leader_client =
            MpcHelperClient::new(peers_conf.get(&leader_id).unwrap().origin.clone());
        let create_data = QueryConfig {
            field_type: FieldType::Fp31,
            query_type: QueryType::TestMultiply,
        };

        // create query
        let (query_id, _, _, _) = join!(
            leader_client.create_query(create_data),
            leader_processor.handle_next(),
            follower1_processor.handle_next(),
            follower2_processor.handle_next()
        );
        let _query_id = query_id.unwrap();

        // send input
        // TODO...
    }
}
