pub mod discovery;
mod server;

use crate::{
    helpers::{
        transport::{
            http::{
                discovery::peer,
                server::{BindTarget, MpcHelperServer},
            },
            Error, SubscriptionType, Transport, TransportCommand,
        },
        HelperIdentity,
    },
    protocol::QueryId,
    sync::{Arc, Mutex},
    task::JoinHandle,
};
use async_trait::async_trait;
use futures::Stream;
use std::collections::{hash_map::Entry, HashMap};
use std::net::SocketAddr;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

pub struct HttpTransport {
    id: HelperIdentity,
    peers_conf: &'static HashMap<HelperIdentity, peer::Config>,
    subscribe_receiver: Arc<Mutex<Option<mpsc::Receiver<TransportCommand>>>>,
    ongoing_queries: Arc<Mutex<HashMap<QueryId, mpsc::Sender<TransportCommand>>>>,
    server: MpcHelperServer,
}

impl HttpTransport {
    pub fn new<St: Stream<Item = TransportCommand> + Send + 'static + Unpin>(
        id: HelperIdentity,
        peers_conf: &'static HashMap<HelperIdentity, peer::Config>,
    ) -> Arc<Self> {
        let (subscribe_sender, subscribe_receiver) = mpsc::channel(1);
        let ongoing_queries = Arc::new(Mutex::new(HashMap::new()));
        let server = MpcHelperServer::new(subscribe_sender, Arc::clone(&ongoing_queries));
        Arc::new(Self {
            id,
            peers_conf,
            subscribe_receiver: Arc::new(Mutex::new(Some(subscribe_receiver))),
            ongoing_queries,
            server,
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
    type CommandStream = ReceiverStream<TransportCommand>;

    fn subscribe(&self, subscription_type: SubscriptionType) -> Self::CommandStream {
        match subscription_type {
            SubscriptionType::Administration => ReceiverStream::new(
                self.subscribe_receiver
                    .lock()
                    .unwrap()
                    .take()
                    .expect("subscribe should only be called once"),
            ),
            SubscriptionType::Query(query_id) => {
                let mut ongoing_networks = self.ongoing_queries.lock().unwrap();
                match ongoing_networks.entry(query_id) {
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

    async fn send(
        &self,
        _destination: &HelperIdentity,
        _command: TransportCommand,
    ) -> Result<(), Error> {
        todo!()
    }
}
