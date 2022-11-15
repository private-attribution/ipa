use crate::{
    helpers::{
        network::{MessageChunks, Network, NetworkSink},
        Role,
    },
    net::{
        client::HttpSendMessagesArgs,
        discovery::{peer, PeerDiscovery},
        MpcHelperClient,
    },
    protocol::QueryId,
};
use axum::body::Bytes;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// Http implementation of a [`Network`]. Uses channels for both [`Sink`] and [`Stream`]
/// implementations.
/// # Panics
/// if `recv_stream` or `recv_messages` called more than once.
#[allow(dead_code)] // TODO: WIP
pub struct HttpNetwork<'a> {
    peers: &'a [peer::Config; 3],
    query_id: QueryId,
    sink_sender: mpsc::Sender<MessageChunks>,
    message_stream_sender: mpsc::Sender<MessageChunks>,
    message_stream_receiver: Arc<Mutex<Option<mpsc::Receiver<MessageChunks>>>>,
}

impl<'a> HttpNetwork<'a> {
    /// * Creates an [`HttpNetwork`]
    /// * spawns a task that consumes incoming data from the infra layer intended for other helpers
    #[must_use]
    #[allow(unused)]
    pub fn new<'b: 'a, D: PeerDiscovery>(
        role: Role,
        peer_discovery: &'b D,
        query_id: QueryId,
    ) -> Self {
        let (stx, mut srx) = mpsc::channel(1);
        let (mstx, msrx) = mpsc::channel(1);
        let network = HttpNetwork {
            peers: peer_discovery.peers(),
            query_id,
            sink_sender: stx,
            message_stream_sender: mstx,
            message_stream_receiver: Arc::new(Mutex::new(Some(msrx))),
        };

        let clients = network.clients(role);
        tokio::spawn(async move {
            while let Some((channel_id, messages)) = srx.recv().await {
                let args = HttpSendMessagesArgs {
                    query_id,
                    step: &channel_id.step,
                    // TODO: fix offset
                    offset: 0,
                    messages: Bytes::from(messages),
                };
                clients[channel_id.role]
                    .send_messages(args)
                    .await
                    .unwrap_or_else(|err| {
                        tracing::error!("could not send message to client: {err}");
                    });
            }
        });
        network
    }

    #[must_use]
    #[allow(unused)]
    pub fn message_stream_sender(&self) -> mpsc::Sender<MessageChunks> {
        self.message_stream_sender.clone()
    }

    #[allow(unused)]
    fn clients(&self, role: Role) -> [MpcHelperClient; 3] {
        self.peers
            .iter()
            .map(|peer_conf| {
                // no https for now
                MpcHelperClient::new(peer_conf.http.origin.clone(), role)
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

impl<'a> Network for HttpNetwork<'a> {
    type Sink = NetworkSink<MessageChunks>;

    type MessageStream = ReceiverStream<MessageChunks>;

    fn sink(&self) -> Self::Sink {
        Self::Sink::new(self.sink_sender.clone())
    }

    fn recv_stream(&self) -> Self::MessageStream {
        ReceiverStream::new(
            self.message_stream_receiver
                .lock()
                .unwrap()
                .take()
                .expect("recv_stream called more than once"),
        )
    }
}
