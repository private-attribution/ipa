mod server;

use crate::{
    helpers::{
        transport::{Error, SubscriptionType, Transport, TransportCommand},
        HelperIdentity,
    },
    net::discovery::peer,
    protocol::QueryId,
    sync::{Arc, Mutex},
};
use async_trait::async_trait;
use futures::Stream;
use futures_util::StreamExt;
use std::collections::{hash_map::Entry, HashMap};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

pub struct HttpTransport {
    id: HelperIdentity,
    peers_conf: &'static [peer::Config; 3],
    subscribe_receiver: Arc<Mutex<Option<mpsc::Receiver<TransportCommand>>>>,
    ongoing_queries: Arc<Mutex<HashMap<QueryId, mpsc::Sender<TransportCommand>>>>,
}

impl HttpTransport {
    pub fn new<St: Stream<Item = TransportCommand> + Send + 'static + Unpin>(
        id: HelperIdentity,
        peers_conf: &'static [peer::Config; 3],
        // represents incoming HTTP requests
        req_handler_stream: St,
    ) -> Arc<Self> {
        let (subscribe_sender, subscribe_receiver) = mpsc::channel(1);
        let ongoing_queries = Arc::new(Mutex::new(HashMap::new()));
        Self::consume_req_handler_stream(
            req_handler_stream,
            Arc::clone(&ongoing_queries),
            subscribe_sender.clone(),
        );
        Arc::new(Self {
            id,
            peers_conf,
            subscribe_receiver: Arc::new(Mutex::new(Some(subscribe_receiver))),
            ongoing_queries,
        })
    }

    fn consume_req_handler_stream<St: Stream<Item = TransportCommand> + Send + 'static + Unpin>(
        mut req_handler_stream: St,
        ongoing_queries: Arc<Mutex<HashMap<QueryId, mpsc::Sender<TransportCommand>>>>,
        subscribe_sender: mpsc::Sender<TransportCommand>,
    ) {
        tokio::spawn(async move {
            while let Some(command) = req_handler_stream.next().await {
                match command {
                    TransportCommand::NetworkEvent(data) => {
                        // ensure `MutexGuard` is dropped before `.await`
                        let transport_sender = {
                            ongoing_queries
                                .lock()
                                .unwrap()
                                .get(&data.query_id)
                                .map(Clone::clone)
                        };
                        if let Some(transport_sender) = transport_sender {
                            transport_sender
                                .send(TransportCommand::NetworkEvent(data))
                                .await
                                .unwrap();
                        } else {
                            tracing::error!(
                                "received message intended for query {}, but query did not exist",
                                data.query_id.as_ref()
                            );
                        }
                    }
                    other => subscribe_sender.send(other).await.unwrap(),
                }
            }
        });
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
        destination: &HelperIdentity,
        command: TransportCommand,
    ) -> Result<(), Error> {
        todo!()
    }
}
