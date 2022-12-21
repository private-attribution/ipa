pub mod discovery;
mod server;

use crate::{
    helpers::{
        transport::{
            http::server::MpcHelperServer, Error, SubscriptionType, Transport, TransportCommand,
        },
        HelperIdentity,
    },
    net::discovery::peer,
    protocol::QueryId,
    sync::{Arc, Mutex},
};
use async_trait::async_trait;
use futures::Stream;
use std::collections::{hash_map::Entry, HashMap};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

pub struct HttpTransport {
    id: HelperIdentity,
    peers_conf: &'static [peer::Config; 3],
    subscribe_receiver: Arc<Mutex<Option<mpsc::Receiver<TransportCommand>>>>,
    ongoing_queries: Arc<Mutex<HashMap<QueryId, mpsc::Sender<TransportCommand>>>>,
    server: MpcHelperServer,
}

impl HttpTransport {
    pub fn new<St: Stream<Item = TransportCommand> + Send + 'static + Unpin>(
        id: HelperIdentity,
        peers_conf: &'static [peer::Config; 3],
    ) -> Arc<Self> {
        let (subscribe_sender, subscribe_receiver) = mpsc::channel(1);
        let ongoing_queries = Arc::new(Mutex::new(HashMap::new()));
        let server = MpcHelperServer::new(subscribe_sender, Arc::clone(&ongoing_queries));
        // server.bind() // TODO
        Arc::new(Self {
            id,
            peers_conf,
            subscribe_receiver: Arc::new(Mutex::new(Some(subscribe_receiver))),
            ongoing_queries,
            server,
        })
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
                let (tx, rx) = mpsc::channel(1);
                let mut ongoing_networks = self.ongoing_queries.lock().unwrap();
                match ongoing_networks.entry(query_id) {
                    Entry::Occupied(_) => {
                        panic!("attempted to subscribe to commands for query id {}, but there is already a previous subscriber", query_id.as_ref())
                    }
                    Entry::Vacant(entry) => {
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
