use crate::{
    helpers::{
        query::QueryCommand,
        transport::{
            http::{
                client::MpcHelperClient,
                discovery::peer,
                server::{BindTarget, MpcHelperServer},
            },
            SubscriptionType, Transport, TransportCommand, TransportError,
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
    peers_conf: &'static HashMap<HelperIdentity, peer::Config>,
    subscribe_receiver: Arc<Mutex<Option<mpsc::Receiver<CommandEnvelope>>>>,
    ongoing_queries: Arc<Mutex<HashMap<QueryId, mpsc::Sender<CommandEnvelope>>>>,
    server: MpcHelperServer,
    clients: HashMap<HelperIdentity, MpcHelperClient>,
}

impl HttpTransport {
    #[must_use]
    pub fn new(
        id: HelperIdentity,
        peers_conf: &'static HashMap<HelperIdentity, peer::Config>,
    ) -> Arc<Self> {
        let (subscribe_sender, subscribe_receiver) = mpsc::channel(1);
        let ongoing_queries = Arc::new(Mutex::new(HashMap::new()));
        let server = MpcHelperServer::new(subscribe_sender, Arc::clone(&ongoing_queries));
        let clients = MpcHelperClient::from_conf(peers_conf);
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
    ) -> Result<(), TransportError> {
        let client = self
            .clients
            .get(destination)
            .ok_or_else(|| TransportError::UnknownHelper(destination.clone()))?;
        let command = command.into();
        let command_name = command.name();
        match command {
            TransportCommand::Query(QueryCommand::Prepare(data, resp)) => {
                let query_id = data.query_id;
                client
                    .prepare_query(&self.id, data)
                    .await
                    .map_err(|inner| TransportError::SendFailed {
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
                .map_err(|err| TransportError::SendFailed {
                    command_name: Some(command_name),
                    query_id: Some(query_id),
                    inner: err.into(),
                }),
            TransportCommand::Query(QueryCommand::Create(_, _) | QueryCommand::Input(_, _)) => {
                Err(TransportError::ExternalCommandSent { command_name })
            }
        }
    }
}

#[cfg(test)]
mod e2e_tests {
    use super::*;
    // use crate::ff::FieldType;
    // use crate::helpers::query::{QueryConfig, QueryType};
    // use crate::helpers::transport::http::discovery;
    // use crate::helpers::transport::http::discovery::PeerDiscovery;
    use crate::query::Processor;
    // use crate::test_fixture::net::localhost_config_map;
    // use futures_util::future::join_all;

    fn open_port() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    async fn make_processors(
        conf: &'static HashMap<HelperIdentity, peer::Config>,
    ) -> HashMap<HelperIdentity, Processor<Arc<HttpTransport>>> {
        let ids: [HelperIdentity; 3] = conf
            .keys()
            .map(Clone::clone)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let mut processors = HashMap::with_capacity(ids.len());
        for this_id in ids.clone() {
            let transport = HttpTransport::new(this_id.clone(), conf);
            let processor = Processor::new(transport, ids.clone()).await;
            processors.insert(this_id, processor);
        }
        processors
    }

    // #[tokio::test]
    // async fn happy_case() {
    //     static CONF: discovery::conf::Conf =
    //         localhost_config_map([open_port(), open_port(), open_port()]);
    //     let peers_conf = CONF.peers_map();
    //     let ps = make_processors(peers_conf).await;
    //     // send a create query command
    //     let leader_id = ps.keys().next().unwrap();
    //     let leader_client = MpcHelperClient::new(peers_conf.get(leader_id).unwrap().origin.clone());
    //     let create_data = QueryConfig {
    //         field_type: FieldType::Fp31,
    //         query_type: QueryType::TestMultiply,
    //     };
    //     let query_id = leader_client.create_query(create_data).await.unwrap();
    // }
}
