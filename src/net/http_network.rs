use crate::sync::{Arc, Mutex};
use crate::{
    helpers::network::{MessageChunks, Network, NetworkSink},
    net::{
        discovery::{peer, PeerDiscovery},
        MpcHelperClient,
    },
    protocol::QueryId,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// Http implementation of a [`Network`]. Uses channels for both [`Sink`] and [`Stream`]
/// implementations.
/// # Panics
/// if `recv_stream` or `recv_messages` called more than once.
#[allow(dead_code)] // TODO: WIP
pub struct HttpNetwork {
    query_id: QueryId,
    sink_sender: mpsc::Sender<MessageChunks>,
    sink_receiver: Arc<Mutex<Option<mpsc::Receiver<MessageChunks>>>>,
    message_stream_sender: mpsc::Sender<MessageChunks>,
    message_stream_receiver: Arc<Mutex<Option<mpsc::Receiver<MessageChunks>>>>,
}

impl HttpNetwork {
    #[must_use]
    #[allow(unused)]
    pub fn new<D: PeerDiscovery>(peer_discovery: &D, query_id: QueryId) -> Self {
        let (stx, srx) = mpsc::channel(1);
        let (mstx, msrx) = mpsc::channel(1);
        let network = HttpNetwork {
            query_id,
            sink_sender: stx,
            sink_receiver: Arc::new(Mutex::new(Some(srx))),
            message_stream_sender: mstx,
            message_stream_receiver: Arc::new(Mutex::new(Some(msrx))),
        };

        // TODO: use the clients
        let peers_config = peer_discovery.peers();
        let _clients = Self::clients(peers_config);

        network
    }

    /// as this does not initialize the clients, it does not initialize the read-side of the
    /// [`Sink`]. This allows tests to grab the read-side directly, bypassing the HTTP layer.
    #[must_use]
    #[cfg(test)]
    pub fn new_without_clients(query_id: QueryId, buffer_size: Option<usize>) -> Self {
        let (stx, srx) = mpsc::channel(buffer_size.unwrap_or(1));
        let (mstx, msrx) = mpsc::channel(buffer_size.unwrap_or(1));
        HttpNetwork {
            query_id,
            sink_sender: stx,
            sink_receiver: Arc::new(Mutex::new(Some(srx))),
            message_stream_sender: mstx,
            message_stream_receiver: Arc::new(Mutex::new(Some(msrx))),
        }
    }

    /// TODO: implement event loop for receiving.
    ///       this function will be removed when that loop exists
    /// # Panics
    /// if called more than once
    #[must_use]
    #[allow(unused)] // See TODO
    pub fn recv_messages(&self) -> mpsc::Receiver<MessageChunks> {
        self.sink_receiver
            .lock()
            .unwrap()
            .take()
            .expect("recv_messages called more than once")
    }

    #[must_use]
    #[allow(unused)]
    pub fn message_stream_sender(&self) -> mpsc::Sender<MessageChunks> {
        self.message_stream_sender.clone()
    }

    fn clients(peers_conf: &[peer::Config; 3]) -> [MpcHelperClient; 3] {
        peers_conf
            .iter()
            .map(|peer_conf| {
                // no https for now
                MpcHelperClient::new(peer_conf.http.origin.clone())
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

impl Network for HttpNetwork {
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
