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
                    .prepare_query(destination, data)
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
                .step(destination, query_id, step, payload, offset)
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
